"""params.nuclei_scan — EXECUTION COMPLETION and REQUEST COVERAGE are two independent facts.

The OTC 20260725 run proved why they must be separated: at ~610k requests per chunk a generic stderr
signature always matched, every chunk read PARTIAL, no chunk was ever recorded done, `chunks` stayed `{}`
(a resume would repeat 8.5h), and the REAL gap — 92.44% of planned requests sent, 459,930 dropped by
nuclei's `-mhe` host-error skip — was never measured. Status now tracks execution; coverage rides
structured counters. Pure/offline (exec_tool is faked; no nuclei, no network).
"""
import json

import pytest

from quarry_recon import events, settings
from quarry_recon.phases import params
from quarry_recon.phases.params import (_NUCLEI_MHE_DEFAULT, _nuclei_cmd, _nuclei_mhe, _nuclei_progress)
from quarry_recon.runner import RunResult, Status

pytestmark = pytest.mark.offline

_NOKEY = object()          # sentinel: PERFORMANCE has no NUCLEI_MAX_HOST_ERROR key at all

# A realistic tail of nuclei's stderr: ANSI-coloured [INF] lines, periodic -stats JSON, and the terminal
# `Scan completed in` line — with the final stats line printed AFTER it, exactly as the real tool does.
_STAT = ('{"duration":"0:54:29","errors":"5635","hosts":"50","matched":"0","percent":"99",'
         '"requests":"605552","rps":"185","startedAt":"2026-07-25T18:00:57Z","templates":"5816",'
         '"total":"610900"}')


def _stderr(*, completed=True, stats=True, extra_tail=0) -> str:
    lines = []
    if stats:
        lines += [_STAT.replace('"requests":"605552"', '"requests":"400000"'), _STAT]
    if completed:
        lines.append("[\x1b[34mINF\x1b[0m] Scan completed in 54m. 0 matches found.")
    lines += [f"[\x1b[34mINF\x1b[0m] Skipped host{i} from target list as found unresponsive permanently"
              for i in range(extra_tail)]
    if stats:
        lines.append(_STAT)
    return "\n".join(lines) + "\n"


class TestNucleiProgress:
    def test_completion_marker_detected_through_ansi(self):
        assert _nuclei_progress(_stderr())["completed"] is True

    def test_no_results_variant_also_completes(self):
        assert _nuclei_progress("[INF] Scan completed in 269ms. No results found.")["completed"] is True

    def test_missing_marker_is_not_complete(self):
        assert _nuclei_progress(_stderr(completed=False))["completed"] is False

    def test_marker_survives_a_trailing_inf_burst(self):
        # the whole point of reading the FULL stderr file: an 8-line tail would evict the marker
        text = _stderr(extra_tail=40)
        assert _nuclei_progress(text)["completed"] is True
        tail8 = "\n".join(text.strip().splitlines()[-8:])
        assert _nuclei_progress(tail8)["completed"] is False        # the tail alone would LIE

    def test_last_stats_line_wins_and_strings_become_ints(self):
        p = _nuclei_progress(_stderr())
        assert (p["planned"], p["requests"], p["errors"]) == (610900, 605552, 5635)

    def test_no_stats_yields_no_counters(self):
        p = _nuclei_progress("[INF] Scan completed in 1s. No results found.")
        assert p["completed"] is True and p["planned"] is None and p["requests"] is None

    def test_empty_and_malformed_input_is_safe(self):
        for bad in ("", "not json", "{nope}", '{"requests":"x","total":"y"}', '["requests","total"]'):
            p = _nuclei_progress(bad)
            assert p["planned"] is None and p["requests"] is None

    def test_stats_line_without_the_needed_keys_is_ignored(self):
        assert _nuclei_progress('{"duration":"0:01:00","rps":"5"}')["planned"] is None

    def test_impossible_counters_pass_through_raw(self):
        # never repaired into a plausible lie — events.coverage_partial's validator flags it UNKNOWN
        p = _nuclei_progress('{"requests":"99","total":"10"}')
        assert (p["planned"], p["requests"]) == (10, 99)


class TestNucleiMaxHostError:
    def _perf(self, monkeypatch, val):
        monkeypatch.setattr(settings, "performance",
                            lambda: {} if val is _NOKEY else {"NUCLEI_MAX_HOST_ERROR": val})

    @pytest.mark.parametrize("raw,expect", [
        (_NOKEY, 0), (None, 0),                                    # unset -> FULL DEPTH, not nuclei's 30
        (30, 30), (5, 5), (1, 1), (100_000, 100_000),              # an explicit bounded policy is honoured
        (0, 0),                                                    # 0 = full depth (-nmhe), a REAL value
        (True, 0), (False, 0),                                     # bool rejected (not 1, not full-depth)
        (-1, 0), (100_001, 0), (10**9, 0), (30.5, 0),             # negative / oversized / float -> default
        ("30", 30), ("0", 0), ("7", 7),                            # clean int strings accepted
        ("abc", 0), ("30.5", 0), ("-1", 0), ("  ", 0),            # garbage -> default
    ])
    def test_parse_is_strict_and_bounded(self, monkeypatch, raw, expect):
        self._perf(monkeypatch, raw)
        assert _nuclei_mhe() == expect

    def test_default_is_full_depth_not_nucleis_own(self):
        # review#P1.3 / coverage-first: unset must mean -nmhe. nuclei's native default of 30 silently drops an
        # erroring host — on the OTC run that suppressed 459,930 requests without ever being asked for.
        assert _NUCLEI_MHE_DEFAULT == 0

    def test_cmd_passes_mhe_when_bounded(self):
        cmd = _nuclei_cmd("t.txt", "o.jsonl", type("P", (), {"http_rl": 0})(), 7)
        assert cmd[cmd.index("-mhe") + 1] == "7" and "-nmhe" not in cmd

    def test_cmd_passes_nmhe_for_full_depth(self):
        cmd = _nuclei_cmd("t.txt", "o.jsonl", type("P", (), {"http_rl": 0})(), 0)
        assert "-nmhe" in cmd and "-mhe" not in cmd

    def test_mhe_is_in_the_resume_fingerprint(self):
        # a coverage policy change must INVALIDATE resume, not silently continue a shallower generation
        a = events.work_unit("params.nuclei_scan", inputs={"hosts": ["a"]}, config={"chunk": 50, "mhe": 30})
        b = events.work_unit("params.nuclei_scan", inputs={"hosts": ["a"]}, config={"chunk": 50, "mhe": 0})
        assert a != b


class _Ctx:
    def __init__(self, d):
        self._d, self.http_timeout, self.run, self.dir = d, 60, self, d
        self.echoed = []

    def raw_path(self, ph, tl, nm):
        p = self._d / "raw" / ph / tl / nm
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def write_list(self, nm, it):
        p = self._d / "work" / nm
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join(it))
        return p

    def add(self, *a, **k):
        return True

    def echo(self, m):
        self.echoed.append(m)


class TestExecutionVsCoverage:
    """Behavioral: run the scan against a fake nuclei and assert the STATE and the EVENTS."""

    def _run(self, tmp_path, monkeypatch, exec_fn, hosts=5, chunk=2):
        from types import SimpleNamespace
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(settings, "concurrency", lambda k, d=None: chunk if k == "NUCLEI_CHUNK_HOSTS" else d)
        monkeypatch.setattr(settings, "workers", lambda t, d: d)
        monkeypatch.setattr(settings, "performance", lambda: {})
        monkeypatch.setattr(params, "exec_tool", exec_fn)
        # The work unit folds a fingerprint of the INSTALLED nuclei template set, and an UNREADABLE state
        # correctly makes the unit non-resumable (a fresh nonce): an unknown template set must never be
        # treated as unchanged. That production behaviour is proven by
        # `test_workunit.py::TestNucleiTemplateFingerprint::test_unknown_template_state_is_non_resumable`
        # and is deliberately untouched here.
        #
        # These tests are about RESUME, so they must not silently depend on whether the machine running
        # them happens to have ~/.config/nuclei. On a clean CI runner the fingerprint is None, every run
        # gets a new work unit, and four resume tests failed for a reason that had nothing to do with
        # what they assert. Pinning it makes the fixture state the precondition instead of inheriting it.
        monkeypatch.setattr(params, "_nuclei_templates_fp", lambda: "test-templates-v1")
        ctx = _Ctx(tmp_path)
        f = ctx.raw_path("params", "nuclei", "findings.jsonl")
        lg = ctx.raw_path("params", "nuclei", "nuclei.run.log")
        res = params._nuclei_scan(ctx, [f"h{i}" for i in range(hosts)], f, lg, SimpleNamespace(http_rl=0))
        return ctx, res

    def _state(self, tmp_path):
        p = tmp_path / "raw" / "params" / "nuclei" / "chunks.state.json"
        return json.loads(p.read_text()) if p.exists() else {}

    def _events(self, tmp_path):
        p = tmp_path / "events.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    def _fake(self, *, status, stderr_text, findings=True, exit_code=...):
        """`exit_code` defaults to what the REAL runner would return for `status`: a TIMED_OUT result carries
        exit_code None (the process was killed, it never exited), and that is the fact the no-oracle fallback
        keys on. Passing 0 alongside TIMED_OUT would be a fixture that cannot occur."""
        from pathlib import Path
        if exit_code is ...:
            exit_code = None if status is Status.TIMED_OUT else 0

        def fn(tool, cmd, timeout=None, stderr_path=None, **k):
            cf = Path(cmd[cmd.index("-o") + 1])
            if findings:
                cf.write_text('{"x":1}\n')
            if stderr_path is not None:                        # the real runner persists the FULL stderr here
                stderr_path.parent.mkdir(parents=True, exist_ok=True)
                stderr_path.write_text(stderr_text)
            tail = "\n".join(stderr_text.strip().splitlines()[-8:])
            return RunResult("nuclei", cmd, status, exit_code, 0.1, cf, 1, stderr_tail=tail)
        return fn

    def test_degraded_coverage_with_completed_execution_is_done_and_resumable(self, tmp_path, monkeypatch):
        # THE regression: nuclei finished, but stderr carried transport noise -> generic classifier said PARTIAL.
        # Execution completed, so the chunk MUST be recorded done and the scan MUST NOT read PARTIAL.
        ctx, res = self._run(tmp_path, monkeypatch,
                             self._fake(status=Status.PARTIAL, stderr_text=_stderr()))
        st = self._state(tmp_path)
        assert sorted(st["chunks"]) == ["0", "1", "2"]              # every chunk recorded -> resume skips them
        assert res.status == Status.SUCCESS                          # execution completed for all chunks
        chunk_fin = [e for e in self._events(tmp_path)
                     if e["event"] == "tool_finish" and not e.get("discovery_context")]
        assert {e["status"] for e in chunk_fin} == {"success"}      # findings present -> SUCCESS, not PARTIAL

    def test_completed_execution_still_reports_the_request_gap(self, tmp_path, monkeypatch):
        self._run(tmp_path, monkeypatch, self._fake(status=Status.PARTIAL, stderr_text=_stderr()))
        cov = [e for e in self._events(tmp_path)
               if e["event"] == "coverage_partial" and e.get("measure") == "requests"]
        assert len(cov) == 3 and {c["unit"] for c in cov} == {"chunk_0", "chunk_1", "chunk_2"}
        for c in cov:
            assert (c["eligible"], c["tested"], c["omitted"]) == (610900, 605552, 5348)
            assert c["coverage_valid"] is True and c["kind"] == events.COVERAGE_TIMEOUT

    def test_coverage_is_persisted_and_reported_in_the_echo_line(self, tmp_path, monkeypatch):
        ctx, _ = self._run(tmp_path, monkeypatch, self._fake(status=Status.PARTIAL, stderr_text=_stderr()))
        assert self._state(tmp_path)["coverage"]["0"] == {"planned": 610900, "requests": 605552}
        assert any("nuclei coverage:" in m and "planned request(s) sent" in m for m in ctx.echoed)

    def test_incomplete_execution_stays_retryable(self, tmp_path, monkeypatch):
        # the process did NOT reach its own end (nonzero exit = crash) -> NOT done
        _, res = self._run(tmp_path, monkeypatch,
                           self._fake(status=Status.PARTIAL, stderr_text=_stderr(), exit_code=2))
        assert self._state(tmp_path)["chunks"] == {}                 # nothing recorded -> a resume re-runs
        assert res.status == Status.PARTIAL and "retryable" in res.note

    def test_incomplete_execution_keeps_its_findings_as_evidence(self, tmp_path, monkeypatch):
        self._run(tmp_path, monkeypatch,
                  self._fake(status=Status.PARTIAL, stderr_text=_stderr(), exit_code=2))
        st = self._state(tmp_path)
        assert st["chunks"] == {}                                     # not done...
        assert sorted(st["evidence"]) == ["0", "1", "2"]              # ...but the output is preserved
        agg = tmp_path / "raw" / "params" / "nuclei" / "findings.jsonl"
        assert agg.read_text().count('{"x":1}') == 3

    def test_reworded_terminal_with_stats_still_completes(self, tmp_path, monkeypatch):
        """review#P1.4: THE regression. A nuclei release that keeps the -stats JSON but rewords only its
        `Scan completed in …` terminal must NOT make every chunk retryable forever — that would recreate the
        8.5-hour resume bug through a PARTIAL format change. Execution completion is exit 0, full stop; the
        terminal sentence is corroborating telemetry. Counters are still RETAINED (stats were recognized), so
        this is emphatically NOT a coverage:unknown case."""
        text = _stderr(completed=False) + "[INF] Scanning finished in 54m — 0 hits (reworded upstream)\n"
        _, res = self._run(tmp_path, monkeypatch,
                           self._fake(status=Status.PARTIAL, stderr_text=text))   # exit 0
        assert sorted(self._state(tmp_path)["chunks"]) == ["0", "1", "2"]          # resumable
        assert res.status == Status.SUCCESS
        cov = [e for e in self._events(tmp_path)
               if e["event"] == "coverage_partial" and e.get("measure") == "requests"]
        assert len(cov) == 3
        for c in cov:                                                 # counters RETAINED, not discarded
            assert (c["eligible"], c["tested"]) == (610900, 605552) and c["coverage_valid"] is True
            assert c["kind"] == events.COVERAGE_TIMEOUT
            assert "terminal not recognized" in c["reason"]            # ...and the anomaly is still reported
        assert self._state(tmp_path)["coverage"]["0"] == {"planned": 610900, "requests": 605552}

    @pytest.mark.parametrize("status,exit_code", [(Status.PARTIAL, 2), (Status.FAILED, 1),
                                                 (Status.TIMED_OUT, None)])
    def test_stats_present_but_process_did_not_finish_is_retryable(self, tmp_path, monkeypatch,
                                                                  status, exit_code):
        """review#P1.4 other half: recognized stats do NOT make a killed/crashed chunk done."""
        _, res = self._run(tmp_path, monkeypatch,
                           self._fake(status=status, stderr_text=_stderr(), exit_code=exit_code))
        assert self._state(tmp_path)["chunks"] == {} and res.status == Status.PARTIAL

    def test_nonzero_exit_after_a_completion_line_is_not_done(self, tmp_path, monkeypatch):
        # nuclei printed its terminal but then failed to exit cleanly — do not trust it as complete
        _, res = self._run(tmp_path, monkeypatch,
                           self._fake(status=Status.PARTIAL, stderr_text=_stderr(), exit_code=2))
        assert self._state(tmp_path)["chunks"] == {} and res.status == Status.PARTIAL

    def test_completed_execution_with_no_findings_is_empty_not_success(self, tmp_path, monkeypatch):
        _, res = self._run(tmp_path, monkeypatch,
                           self._fake(status=Status.PARTIAL, stderr_text=_stderr(), findings=False))
        chunk_fin = [e for e in self._events(tmp_path)
                     if e["event"] == "tool_finish" and not e.get("discovery_context")]
        assert {e["status"] for e in chunk_fin} == {"empty"}
        assert res.status == Status.SUCCESS                           # execution complete -> scan is clean

    def test_silent_progress_channel_completes_on_exit_zero(self, tmp_path, monkeypatch):
        # FAIL-SAFE: nuclei said nothing recognizable at all. exit 0 still means the process reached its
        # own end, so the chunk is resumable; only its COVERAGE is unknown.
        _, res = self._run(tmp_path, monkeypatch, self._fake(status=Status.SUCCESS, stderr_text=""))
        assert sorted(self._state(tmp_path)["chunks"]) == ["0", "1", "2"]
        assert res.status == Status.SUCCESS

    def test_silent_progress_channel_with_a_killed_run_is_not_done(self, tmp_path, monkeypatch):
        # no oracle, and the process never exited (TIMED_OUT -> exit_code None) -> NOT complete
        _, res = self._run(tmp_path, monkeypatch, self._fake(status=Status.TIMED_OUT, stderr_text=""))
        assert self._state(tmp_path)["chunks"] == {} and res.status == Status.PARTIAL

    def test_no_oracle_falls_back_to_exit_code_not_status(self, tmp_path, monkeypatch):
        """review#P1.2: the fallback must NOT consult res.status. The generic classifier turns exit 0 plus an
        ordinary `i/o timeout` line into PARTIAL, so a status-based fallback would recreate permanent
        non-resumability the moment nuclei's completion wording changed."""
        noise = "[INF] some future wording nobody parses\n[ERR] read tcp: i/o timeout\n"
        _, res = self._run(tmp_path, monkeypatch,
                           self._fake(status=Status.PARTIAL, stderr_text=noise))   # exit 0, classifier says PARTIAL
        assert sorted(self._state(tmp_path)["chunks"]) == ["0", "1", "2"]           # still resumable
        assert res.status == Status.SUCCESS
        cov = [e for e in self._events(tmp_path)
               if e["event"] == "coverage_partial" and e.get("measure") == "requests"]
        # ...but coverage is UNKNOWN, never assumed complete
        assert cov and all(c["kind"] == events.COVERAGE_UNKNOWN and c["coverage_valid"] is False for c in cov)

    def test_nonzero_exit_with_no_oracle_is_not_done(self, tmp_path, monkeypatch):
        _, res = self._run(tmp_path, monkeypatch,
                           self._fake(status=Status.SUCCESS, stderr_text="", exit_code=3))
        assert self._state(tmp_path)["chunks"] == {} and res.status == Status.PARTIAL

    def test_counters_unavailable_emits_a_reason_only_partial(self, tmp_path, monkeypatch):
        self._run(tmp_path, monkeypatch,
                  self._fake(status=Status.SUCCESS, stderr_text="[INF] Scan completed in 1s. No results found."))
        cov = [e for e in self._events(tmp_path)
               if e["event"] == "coverage_partial" and e.get("measure") == "requests"]
        assert cov and all(c.get("eligible") is None and "unavailable" in c["reason"] for c in cov)

    def test_impossible_counters_surface_as_coverage_unknown(self, tmp_path, monkeypatch):
        bad = '{"requests":"99","total":"10"}\n[INF] Scan completed in 1s. No results found.\n'
        self._run(tmp_path, monkeypatch, self._fake(status=Status.SUCCESS, stderr_text=bad))
        cov = [e for e in self._events(tmp_path)
               if e["event"] == "coverage_partial" and e.get("measure") == "requests"]
        assert cov and all(c["coverage_valid"] is False for c in cov)   # a gap, never fake completion

    def test_per_chunk_stderr_log_is_requested(self, tmp_path, monkeypatch):
        seen = []
        from pathlib import Path

        def fn(tool, cmd, timeout=None, stderr_path=None, **k):
            seen.append(stderr_path)
            cf = Path(cmd[cmd.index("-o") + 1]); cf.write_text('{"x":1}\n')
            if stderr_path is not None:
                stderr_path.parent.mkdir(parents=True, exist_ok=True)
                stderr_path.write_text(_stderr())
            return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        self._run(tmp_path, monkeypatch, fn)
        assert len(seen) == 3 and all(p is not None for p in seen)
        assert [p.name for p in seen] == ["stderr_0.log", "stderr_1.log", "stderr_2.log"]
        assert all(p.is_file() and "Scan completed" in p.read_text() for p in seen)


class TestResumeReportsPersistedCoverage:
    def test_resume_does_not_depend_on_the_DEVELOPERS_nuclei_config(self, tmp_path, monkeypatch):
        """The CI failure, as a test. With no readable nuclei template state — a clean runner, or any
        machine without ~/.config/nuclei — these resume tests used to fail because the work unit carried
        a fresh nonce each run. The harness now pins the fingerprint, so the environment cannot decide
        whether a resume test passes."""
        monkeypatch.setenv("NUCLEI_CONFIG", str(tmp_path / "no-such-nuclei-config"))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no-such-xdg"))
        t = TestExecutionVsCoverage()
        t._run(tmp_path, monkeypatch, t._fake(status=Status.SUCCESS, stderr_text=_stderr()))
        assert sorted(t._state(tmp_path)["chunks"]) == ["0", "1", "2"]

        def never(tool, cmd, **k):
            raise AssertionError("a done chunk was re-run: the work unit changed between runs")
        _, res = t._run(tmp_path, monkeypatch, never)
        assert res.status == Status.SUCCESS

    def test_resumed_chunks_re_emit_their_recorded_coverage(self, tmp_path, monkeypatch):
        """A resume must not understate the run's gap: a chunk it SKIPS still has to report the coverage it
        recorded the first time, or the rollup silently shrinks to only the chunks that re-ran."""
        t = TestExecutionVsCoverage()
        # run 1: everything completes with a request gap
        t._run(tmp_path, monkeypatch, t._fake(status=Status.PARTIAL, stderr_text=_stderr()))
        first = t._state(tmp_path)
        assert sorted(first["chunks"]) == ["0", "1", "2"] and len(first["coverage"]) == 3

        # run 2: same work_unit -> every chunk resumes; exec_tool must NEVER be called
        def never(tool, cmd, **k):
            raise AssertionError("a done chunk was re-run")
        _, res = t._run(tmp_path, monkeypatch, never)
        # events.jsonl accumulates across both runs — select run 2's units by their `resumed` reason
        cov = [e for e in t._events(tmp_path)
               if e["event"] == "coverage_partial" and e.get("measure") == "requests"
               and "resumed" in (e.get("reason") or "")]
        assert len(cov) == 3                                      # re-emitted from persisted state
        assert {c["unit"] for c in cov} == {"chunk_0", "chunk_1", "chunk_2"}
        assert all(c["eligible"] == 610900 and c["tested"] == 605552 for c in cov)
        assert res.status == Status.SUCCESS

    def test_stale_coverage_for_a_rerun_chunk_is_dropped(self, tmp_path, monkeypatch):
        """A coverage record only means something for a COMPLETED chunk. If the chunk is going to re-run, last
        attempt's numbers must not stand in for this one when the re-run reports no parseable stats line."""
        t = TestExecutionVsCoverage()
        # run 1: execution INCOMPLETE -> nothing done, but plant a coverage record as if a prior attempt left one
        t._run(tmp_path, monkeypatch, t._fake(status=Status.PARTIAL, stderr_text=_stderr(), exit_code=2))
        p = tmp_path / "raw" / "params" / "nuclei" / "chunks.state.json"
        st = json.loads(p.read_text())
        assert st["chunks"] == {}
        st["coverage"] = {"0": {"planned": 999999, "requests": 1}}
        p.write_text(json.dumps(st))
        # run 2: the chunk re-runs and completes, but nuclei reports NO stats -> no counters for it
        ctx, _ = t._run(tmp_path, monkeypatch,
                        t._fake(status=Status.SUCCESS,
                                stderr_text="[INF] Scan completed in 1s. No results found."))
        assert json.loads(p.read_text())["coverage"] == {}          # the stale 999999 is gone, not reused
        assert not any("nuclei coverage:" in m for m in ctx.echoed)

    def test_partial_measurement_is_qualified_in_the_summary(self, tmp_path, monkeypatch):
        """An unqualified percentage over a subset of chunks would read as a whole-scan figure."""
        t = TestExecutionVsCoverage()
        calls = {"n": 0}
        from pathlib import Path

        def mixed(tool, cmd, timeout=None, stderr_path=None, **k):
            calls["n"] += 1
            cf = Path(cmd[cmd.index("-o") + 1]); cf.write_text('{"x":1}\n')
            # only the first chunk reports stats; the rest complete without counters
            txt = _stderr() if calls["n"] == 1 else "[INF] Scan completed in 1s. No results found."
            if stderr_path is not None:
                stderr_path.parent.mkdir(parents=True, exist_ok=True)
                stderr_path.write_text(txt)
            return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        ctx, _ = t._run(tmp_path, monkeypatch, mixed)
        line = next(m for m in ctx.echoed if "nuclei coverage:" in m)
        assert "over 1/3 measured chunk(s)" in line

    def test_corrupt_persisted_coverage_is_dropped_not_trusted(self, tmp_path, monkeypatch):
        t = TestExecutionVsCoverage()
        t._run(tmp_path, monkeypatch, t._fake(status=Status.PARTIAL, stderr_text=_stderr()))
        p = tmp_path / "raw" / "params" / "nuclei" / "chunks.state.json"
        st = json.loads(p.read_text())
        st["coverage"] = {"0": {"planned": -5, "requests": 1}, "1": "nope",
                          "2": {"planned": True, "requests": 1}, "9": {"planned": 1, "requests": 1}}
        p.write_text(json.dumps(st))

        def never(tool, cmd, **k):
            raise AssertionError("a done chunk was re-run")
        t._run(tmp_path, monkeypatch, never)
        cov = [e for e in t._events(tmp_path)
               if e["event"] == "coverage_partial" and e.get("measure") == "requests"
               and "resumed" in (e.get("reason") or "")]
        # every entry was invalid -> counters unavailable, reported as such rather than as a bogus number
        assert len(cov) == 3 and all(c.get("eligible") is None for c in cov)


class TestCoverageUnknownVerdict:
    """review#P1.1: an UNMEASURABLE unit must reach the run VERDICT as a gap.

    Before COVERAGE_UNKNOWN, "coverage unavailable" was a reason-only event. `events.coverage_partial` did not
    open a generation without counters, and `store._read_coverage` admitted only records carrying `eligible` —
    so an unmeasurable source (a) vanished from the rollup, making a first run with no stats read as fully
    covered, and (b) never reset, letting a PRIOR run's counters keep standing in for it. Both made unmeasured
    indistinguishable from complete. These assert the FINAL verdict, not just the emitted event.
    """
    SID = "params.nuclei_scan"

    def _store(self, tmp_path):
        from quarry_recon.store import Run
        events.reset()
        st = Run(tmp_path, "t", run_id="r1")
        events.configure(st.dir)
        return st

    def _cov(self, st):
        s = st._run_summary()
        return s, [g for g in s["gaps"] if g["tool"] == self.SID]

    def test_first_run_with_no_counters_is_a_gap_not_complete(self, tmp_path):
        st = self._store(tmp_path)
        events.coverage_partial(self.SID, kind=events.COVERAGE_UNKNOWN, unit="chunk_0", measure="requests",
                                reason="no stats line")
        s, gaps = self._cov(st)
        assert s["verdict"] == "complete_with_gaps"
        assert len(gaps) == 1 and gaps[0]["status"] == "coverage:unknown"
        assert gaps[0]["why"] == "no stats line"          # the reason survives to the operator

    def test_unavailable_counters_supersede_a_prior_generation(self, tmp_path):
        """The dangerous case: run 1 measured 605552/610900; run 2 cannot measure. Run 2 must NOT report run 1's
        numbers as if they were current."""
        st = self._store(tmp_path)
        events.coverage_partial(self.SID, kind=events.COVERAGE_TIMEOUT, unit="chunk_0", measure="requests",
                                eligible=610900, tested=605552, omitted=5348, reason="run 1 measured")
        s1, g1 = self._cov(st)
        assert g1[0]["status"] == f"coverage:{events.COVERAGE_TIMEOUT}" and g1[0]["omitted"] == 5348

        events.reset()                                    # a NEW session/generation, same run dir
        events.configure(st.dir)
        events.coverage_partial(self.SID, kind=events.COVERAGE_UNKNOWN, unit="chunk_0", measure="requests",
                                reason="stats corrupt this time")
        s2, g2 = self._cov(st)
        assert len(g2) == 1 and g2[0]["status"] == "coverage:unknown"
        assert g2[0]["omitted"] == 0 and g2[0]["eligible"] == 0     # run 1's 5348/610900 is NOT reasserted
        assert g2[0]["why"] == "stats corrupt this time"
        assert s2["verdict"] == "complete_with_gaps"

    def test_mixed_measured_and_unmeasured_chunks_reports_both(self, tmp_path):
        st = self._store(tmp_path)
        events.coverage_partial(self.SID, kind=events.COVERAGE_TIMEOUT, unit="chunk_0", measure="requests",
                                eligible=1000, tested=900, omitted=100, reason="chunk 1 measured")
        events.coverage_partial(self.SID, kind=events.COVERAGE_UNKNOWN, unit="chunk_1", measure="requests",
                                reason="chunk 2 unmeasurable")
        s, gaps = self._cov(st)
        assert s["verdict"] == "complete_with_gaps"
        # the whole rollup is UNKNOWN — a "100 omitted" headline would imply the other chunk was covered
        assert len(gaps) == 1 and gaps[0]["status"] == "coverage:unknown"
        assert "unmeasurable" in gaps[0]["why"]
        cov = next(c for c in s["coverage"] if c["source_id"] == self.SID)
        assert cov["valid"] is False
        assert [u["unit"] for u in cov["units"]] == ["chunk_0"]       # the measured unit's attribution is kept
        assert [u["unit"] for u in cov["unknown"]] == ["chunk_1"]     # ...and so is the unmeasured one's

    def test_all_measured_stays_a_normal_gap(self, tmp_path):
        st = self._store(tmp_path)
        events.coverage_partial(self.SID, kind=events.COVERAGE_TIMEOUT, unit="chunk_0", measure="requests",
                                eligible=1000, tested=1000, omitted=0, reason="fully covered")
        s, gaps = self._cov(st)
        assert gaps == [] and s["verdict"] == "complete"              # omitted==0 -> no gap at all

    def test_unknown_never_becomes_a_soft_limit(self, tmp_path):
        st = self._store(tmp_path)
        events.coverage_partial(self.SID, kind=events.COVERAGE_UNKNOWN, unit="chunk_0", measure="requests",
                                reason="unmeasurable")
        s, _ = self._cov(st)
        assert s["coverage_limits"] == []                             # a LIMIT is operator-chosen; unknown is not


class TestArtifactDigestBinding:
    """review#P3: path validity is not CONTENT validity. A recorded artifact that is edited on disk after being
    marked done satisfied every path check and was still trusted, so a resume skipped the chunk and aggregated
    whatever the file now said."""

    def _first_run(self, tmp_path, monkeypatch):
        t = TestExecutionVsCoverage()
        t._run(tmp_path, monkeypatch, t._fake(status=Status.SUCCESS, stderr_text=_stderr()))
        return t, tmp_path / "raw" / "params" / "nuclei"

    def test_digests_are_recorded_for_every_done_chunk(self, tmp_path, monkeypatch):
        t, nucdir = self._first_run(tmp_path, monkeypatch)
        st = json.loads((nucdir / "chunks.state.json").read_text())
        assert set(st["digests"]) == set(st["chunks"].values())
        assert all(len(v) == 64 for v in st["digests"].values())      # sha256 hex

    def test_edited_artifact_invalidates_the_skip(self, tmp_path, monkeypatch):
        t, nucdir = self._first_run(tmp_path, monkeypatch)
        st = json.loads((nucdir / "chunks.state.json").read_text())
        (nucdir / st["chunks"]["1"]).write_text('{"tampered":1}\n')   # same path, same name, NEW content
        ran = []
        from pathlib import Path

        def track(tool, cmd, timeout=None, stderr_path=None, **k):
            ran.append(Path(cmd[cmd.index("-o") + 1]).name)
            cf = Path(cmd[cmd.index("-o") + 1]); cf.write_text('{"re":1}\n')
            if stderr_path is not None:
                stderr_path.parent.mkdir(parents=True, exist_ok=True); stderr_path.write_text(_stderr())
            return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        t._run(tmp_path, monkeypatch, track)
        assert ran == ["findings_1.jsonl"]                            # ONLY the tampered chunk re-ran
        assert '{"tampered":1}' not in (nucdir / "findings.jsonl").read_text()

    def test_state_without_digests_fails_closed(self, tmp_path, monkeypatch):
        # an older Quarry's state file has no digests -> unverifiable -> re-run, never a trusted skip
        t, nucdir = self._first_run(tmp_path, monkeypatch)
        p = nucdir / "chunks.state.json"
        st = json.loads(p.read_text())
        st.pop("digests")
        p.write_text(json.dumps(st))
        ran = []
        from pathlib import Path

        def track(tool, cmd, timeout=None, stderr_path=None, **k):
            ran.append(Path(cmd[cmd.index("-o") + 1]).name)
            cf = Path(cmd[cmd.index("-o") + 1]); cf.write_text('{"re":1}\n')
            if stderr_path is not None:
                stderr_path.parent.mkdir(parents=True, exist_ok=True); stderr_path.write_text(_stderr())
            return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        t._run(tmp_path, monkeypatch, track)
        assert sorted(ran) == ["findings_0.jsonl", "findings_1.jsonl", "findings_2.jsonl"]

    def test_intact_artifacts_still_resume(self, tmp_path, monkeypatch):
        t, nucdir = self._first_run(tmp_path, monkeypatch)

        def never(tool, cmd, **k):
            raise AssertionError("an intact done chunk was re-run")
        _, res = t._run(tmp_path, monkeypatch, never)
        assert res.status == Status.SUCCESS                            # digest binding must not break resume
