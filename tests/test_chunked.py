"""C07 increment 4 — chunked lanes (nuclei/dalfox) under the contract vocabulary.

Two correctness gains reconciled with their existing custom per-chunk events (no duplicates):
1. resume validity is a WORK_UNIT that folds coverage-affecting CONFIG (severity/etags/mode/chunk), not
   just the input list — so a template-scope / mode change no longer wrongly resumes done chunks.
2. per-chunk events carry a stable work_unit (not the loop index), and the source terminal always fires.
"""
import inspect

import pytest

from quarry_recon.events import work_unit
from quarry_recon.phases import params

pytestmark = pytest.mark.offline


class TestResumeKeyFoldsConfig:
    def test_config_change_yields_new_scan_key(self):
        # same hosts, DIFFERENT coverage config → different work_unit → resume starts fresh (no wrong skip)
        base = work_unit("params.nuclei_scan", inputs={"hosts": ["a", "b"]},
                         config={"severity": "critical,high,medium", "etags": "intrusive", "chunk": 50})
        wider = work_unit("params.nuclei_scan", inputs={"hosts": ["a", "b"]},
                          config={"severity": "critical,high,medium,low", "etags": "intrusive", "chunk": 50})
        assert base != wider

    def test_same_config_same_key(self):
        cfg = {"severity": "critical,high,medium", "etags": "intrusive,fuzz,dos,brute-force", "chunk": 50}
        assert (work_unit("params.nuclei_scan", inputs={"hosts": ["a"]}, config=cfg)
                == work_unit("params.nuclei_scan", inputs={"hosts": ["a"]}, config=cfg))

    def test_chunk_unit_distinct_from_scan_unit(self):
        cfg = {"severity": "s", "chunk": 2}
        scan = work_unit("params.nuclei_scan", inputs={"hosts": ["a", "b", "c"]}, config=cfg)
        chunk = work_unit("params.nuclei_scan", inputs={"hosts": ["a", "b"]}, config=cfg)
        assert scan != chunk                                # scan folds ALL hosts; a chunk folds its subset


class TestSourceStructure:
    @pytest.mark.parametrize("fn", [params._nuclei_scan, params._dalfox_xss_fast])
    def test_resume_key_is_config_inclusive_work_unit(self, fn):
        src = inspect.getsource(fn)
        assert "scan_wu = events.work_unit(" in src         # config-inclusive resume key
        assert '"work_unit": scan_wu' in src                # persisted in chunks.state.json
        assert 'prev.get("work_unit")' in src and "scan_wu" in src   # validity check keys on the work_unit
        assert "hashlib.sha256((" not in src                # the old hosts-only input_hash CODE is gone

    @pytest.mark.parametrize("fn", [params._nuclei_scan, params._dalfox_xss_fast])
    def test_per_chunk_work_unit_on_events(self, fn):
        src = inspect.getsource(fn)
        assert "chunk_wu = events.work_unit(" in src         # a stable per-chunk unit (not the loop index)
        assert "work_unit=chunk_wu" in src                   # tagged on the per-chunk progress event

    @pytest.mark.parametrize("fn", [params._nuclei_scan, params._dalfox_xss_fast])
    def test_source_terminal_guaranteed(self, fn):
        src = inspect.getsource(fn)
        assert "try:" in src and "finally:" in src           # source tool_finish fires even if the loop raises
        assert "events.tool_finish(sid" in src and "work_unit=scan_wu" in src


class _Ctx:
    """Minimal ctx for executing a chunked scan against a fake exec_tool."""
    def __init__(self, d):
        self._d = d
        self.http_timeout = 60
        self.run = self
        self.dir = d

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


class TestChunkedLifecycleBehavior:
    """Execute the scan and assert the emitted EVENTS (not source strings) — the behavioral gap Codex flagged."""

    def _events(self, d):
        import json
        p = d / "events.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    def _run_nuclei(self, tmp_path, monkeypatch, exec_fn):
        from quarry_recon import events, settings
        from types import SimpleNamespace
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(settings, "concurrency", lambda k, d=None: 2 if k == "NUCLEI_CHUNK_HOSTS" else d)
        monkeypatch.setattr(settings, "workers", lambda t, d: d)
        monkeypatch.setattr(params, "exec_tool", exec_fn)
        ctx = _Ctx(tmp_path)
        f = ctx.raw_path("params", "nuclei", "findings.jsonl")
        lg = ctx.raw_path("params", "nuclei", "nuclei.run.log")
        return params._nuclei_scan(ctx, [f"h{i}" for i in range(5)], f, lg, SimpleNamespace(http_rl=0))

    def test_exactly_one_source_terminal_and_per_chunk_lifecycle(self, tmp_path, monkeypatch):
        from quarry_recon.runner import RunResult, Status

        def ok(tool, cmd, timeout=None, **k):
            cf = __import__("pathlib").Path(cmd[cmd.index("-o") + 1]); cf.write_text('{"x":1}\n')
            return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        self._run_nuclei(tmp_path, monkeypatch, ok)
        evs = self._events(tmp_path)
        finishes = [e for e in evs if e["event"] == "tool_finish"]
        starts = [e for e in evs if e["event"] == "tool_start"]
        # 3 chunks: 1 source lifecycle + 3 chunk lifecycles = 4 starts, 4 finishes
        assert len(starts) == 4 and len(finishes) == 4
        # exactly ONE terminal carries the scan work_unit; the other 3 carry distinct chunk work_units
        scan_finishes = [e for e in finishes if e.get("work_unit") == starts[0]["work_unit"]]
        assert len(scan_finishes) == 1                       # exactly-one source terminal
        assert len({e["work_unit"] for e in finishes}) == 4  # 4 distinct units (1 scan + 3 chunks)

    def test_exception_midloop_emits_failed_source_terminal_not_success(self, tmp_path, monkeypatch):
        from quarry_recon.runner import RunResult, Status

        calls = {"n": 0}
        def boom(tool, cmd, timeout=None, **k):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("nuclei blew up on chunk 2")
            cf = __import__("pathlib").Path(cmd[cmd.index("-o") + 1]); cf.write_text('{"x":1}\n')
            return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        with pytest.raises(RuntimeError):
            self._run_nuclei(tmp_path, monkeypatch, boom)
        evs = self._events(tmp_path)
        finishes = [e for e in evs if e["event"] == "tool_finish"]
        # the SOURCE terminal (last finish) must be failed — status started FAILED, loop never reset it
        assert finishes[-1]["status"] == "failed"
        # review#1: the CHUNK that raised must ALSO get its own terminal (a failed chunk_wu), not be left
        # permanently 'started'. Every chunk tool_start must have a matching tool_finish with the same unit.
        starts = [e for e in evs if e["event"] == "tool_start" and e.get("input_total")]
        started_units = {e["work_unit"] for e in starts if e.get("work_unit")}
        finished_units = {e["work_unit"] for e in finishes if e.get("work_unit")}
        assert started_units and started_units <= finished_units       # no chunk left dangling
        # chunk terminals carry NO discovery_context (only the scan terminal does)
        raised_chunk = [e for e in finishes if e["status"] == "failed"
                        and not e.get("discovery_context") and "raised" in (e.get("reason") or "")]
        assert len(raised_chunk) == 1                                   # the crashed chunk's synthetic FAILED terminal

    def test_post_success_bookkeeping_raise_marks_chunk_failed_not_success(self, tmp_path, monkeypatch):
        # review#1: the tool returns SUCCESS, but a POST-execution step (here: the stderr-log write) raises.
        # The chunk terminal must be FAILED — processing was incomplete — NOT the tool's SUCCESS.
        from quarry_recon import events, settings
        from quarry_recon.runner import RunResult, Status
        from types import SimpleNamespace
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(settings, "concurrency", lambda k, d=None: 2 if k == "NUCLEI_CHUNK_HOSTS" else d)
        monkeypatch.setattr(settings, "workers", lambda t, d: d)

        def ok_with_stderr(tool, cmd, timeout=None, **k):
            cf = __import__("pathlib").Path(cmd[cmd.index("-o") + 1]); cf.write_text('{"x":1}\n')
            return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1, stderr_tail="waf")
        monkeypatch.setattr(params, "exec_tool", ok_with_stderr)
        ctx = _Ctx(tmp_path)
        f = ctx.raw_path("params", "nuclei", "findings.jsonl")
        lg = ctx.raw_path("params", "nuclei", "nuclei.run.log")
        lg.mkdir()                                          # log path is a DIRECTORY -> log.open("a") raises post-success
        with pytest.raises(OSError):
            params._nuclei_scan(ctx, [f"h{i}" for i in range(5)], f, lg, SimpleNamespace(http_rl=0))
        chunk_finishes = [e for e in self._events(tmp_path)
                          if e["event"] == "tool_finish" and not e.get("discovery_context")]
        assert chunk_finishes and chunk_finishes[0]["status"] == "failed"   # NOT "success"
        assert "bookkeeping" in (chunk_finishes[0].get("reason") or "")

    def test_dalfox_ingestion_raise_marks_chunk_failed(self, tmp_path, monkeypatch):
        # review#1: dalfox tool returns SUCCESS but run.add() ingestion raises -> chunk terminal FAILED
        from quarry_recon import events, settings
        from quarry_recon.runner import RunResult, Status
        from types import SimpleNamespace
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(settings, "concurrency", lambda k, d=None: 2 if k == "DALFOX_CHUNK" else d)
        monkeypatch.setattr(settings, "workers", lambda t, d: d)
        import quarry_recon.secrets as sec
        monkeypatch.setattr(sec, "oob", lambda: {})
        monkeypatch.setattr(params, "_dalfox_engine_id", lambda: "test-engine")   # no registry.health probe offline

        from pathlib import Path
        def ok_with_poc(tool, cmd, timeout=None, **k):
            # dalfox writes the JSONL to its -o FILE during exec — one valid finding, clean (exit 1 + finding)
            cf = Path(cmd[cmd.index("-o") + 1])
            cf.write_text('{"meta":{"findings_count":1}}\n'
                          '{"type":"R","param":"q","data":"https://h/x?q=1","severity":"Medium",'
                          '"message_str":"reflected q","method":"GET","location":"Query"}\n')
            return RunResult("dalfox", cmd, Status.SUCCESS, 1, 0.1, None, 0)
        monkeypatch.setattr(params, "exec_tool", ok_with_poc)

        class _RaisingCtx(_Ctx):
            def add(self, *a, **k):
                raise RuntimeError("store write failed mid-ingestion")
        # ingestion now happens in the SOURCE-level aggregate; a store-write raise must PROPAGATE and leave the
        # SOURCE terminal FAILED (never a silent success)
        ctx = _RaisingCtx(tmp_path)
        with pytest.raises(RuntimeError):
            params._dalfox_xss_fast(ctx, [f"https://h/{i}?q=1" for i in range(3)], SimpleNamespace(http_rl=0))
        src_finish = [e for e in self._events(tmp_path)
                      if e["event"] == "tool_finish" and e.get("discovery_context")]
        assert src_finish and src_finish[0]["status"] == "failed"

    def test_nonresumable_rerun_does_not_destroy_prior_findings(self, tmp_path, monkeypatch):
        # review#2: unknown template state -> a nonce'd (different) work_unit each run. A CANCELLED rerun must
        # NOT truncate the prior aggregate or delete the prior attempt before its replacement exists.
        from quarry_recon.runner import RunResult, Status
        monkeypatch.setenv("NUCLEI_CONFIG", str(tmp_path / "no-nuclei-config"))   # -> fp None -> nonce

        def ok(tool, cmd, timeout=None, **k):
            cf = __import__("pathlib").Path(cmd[cmd.index("-o") + 1]); cf.write_text('{"run":1}\n')
            return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        nucdir = tmp_path / "raw" / "params" / "nuclei"
        r1 = self._run_nuclei(tmp_path, monkeypatch, ok)      # run 1: all chunks clean
        agg = nucdir / "findings.jsonl"
        first_content = agg.read_text()
        assert r1.status == Status.SUCCESS and first_content.count('{"run":1}') == 3
        wus_after_1 = list(nucdir.glob("wu_*"))
        assert len(wus_after_1) == 1                           # run 1's work-unit dir (immutable)

        calls = {"n": 0}
        def boom(tool, cmd, timeout=None, **k):               # run 2: cancel mid-loop (chunk 2 raises)
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("cancelled rerun")
            cf = __import__("pathlib").Path(cmd[cmd.index("-o") + 1]); cf.write_text('{"run":2}\n')
            return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        with pytest.raises(RuntimeError):
            self._run_nuclei(tmp_path, monkeypatch, boom)
        # the prior aggregate is INTACT (atomic swap never reached) and run-1's work-unit dir still preserved
        assert agg.read_text() == first_content               # not truncated, still run-1 findings
        assert wus_after_1[0].exists()                        # run-1 evidence not pruned by a failed rerun

    def test_stable_template_retry_preserves_original_chunk_artifact(self, tmp_path, monkeypatch):
        # review#4: SAME work_unit (stable templates) retry. A partial first attempt, then a CANCELLED retry of
        # the same work unit — the original clean chunk's artifact AND the aggregate must remain reproducible
        # (the retry writes to a FRESH attempt dir; it can't overwrite or lose the prior attempt's evidence).
        import json as _json
        from quarry_recon.runner import RunResult, Status
        cfgdir = tmp_path / "nuclei-cfg"; cfgdir.mkdir()
        (cfgdir / ".templates-config.json").write_text(_json.dumps({"nuclei-templates-version": "vX"}))
        monkeypatch.setenv("NUCLEI_CONFIG", str(cfgdir))      # deterministic wu (no nonce) -> same wu across runs
        nucdir = tmp_path / "raw" / "params" / "nuclei"

        # attempt 1: chunk 0 clean, chunk 1 execution-INCOMPLETE (retryable), chunk 2 clean.
        # [145]: retryability is now EXECUTION completion, not the classifier's status — a chunk that exited 0
        # is done even if stderr looked degraded. So an incomplete chunk is modelled by a nonzero exit (a real
        # crash/kill), which is what actually leaves work behind.
        def partial(tool, cmd, timeout=None, **k):
            cf = __import__("pathlib").Path(cmd[cmd.index("-o") + 1])
            if "findings_1." in cf.name:
                cf.write_text('{"deg":1}\n'); return RunResult("nuclei", cmd, Status.PARTIAL, 2, 0.1, cf, 1)
            cf.write_text('{"clean":1}\n'); return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        r1 = self._run_nuclei(tmp_path, monkeypatch, partial)
        assert r1.status == Status.PARTIAL
        state = _json.loads((nucdir / "chunks.state.json").read_text())
        assert set(state["chunks"]) == {"0", "2"}             # only clean chunks recorded, mapped to artifacts
        orig0 = nucdir / state["chunks"]["0"]                 # the original clean chunk-0 artifact
        assert orig0.exists() and orig0.read_text() == '{"clean":1}\n'
        agg1 = (nucdir / "findings.jsonl").read_text()

        # attempt 2 (same wu): resume, re-run only the degraded chunk 1 — then CANCEL it
        def cancel_retry(tool, cmd, timeout=None, **k):
            raise RuntimeError("cancelled retry of chunk 1")
        with pytest.raises(RuntimeError):
            self._run_nuclei(tmp_path, monkeypatch, cancel_retry)
        # original clean chunk-0 artifact UNCHANGED, and the aggregate still reproducible from recorded paths
        assert orig0.exists() and orig0.read_text() == '{"clean":1}\n'
        assert (nucdir / "findings.jsonl").read_text() == agg1

    def test_resume_drops_invalid_state_entries_and_reruns(self, tmp_path, monkeypatch):
        # review#1: a recorded artifact that is MISSING, out-of-tree (../ or absolute), or keyed by a malformed
        # index must NOT be a silent successful skip — it is dropped and the chunk RE-RUNS. A malformed key must
        # not crash _completed_hosts() either.
        import json as _json
        from quarry_recon.runner import RunResult, Status
        cfgdir = tmp_path / "nuclei-cfg"; cfgdir.mkdir()
        (cfgdir / ".templates-config.json").write_text(_json.dumps({"nuclei-templates-version": "vX"}))
        monkeypatch.setenv("NUCLEI_CONFIG", str(cfgdir))
        nucdir = tmp_path / "raw" / "params" / "nuclei"

        def ok(tool, cmd, timeout=None, **k):
            cf = __import__("pathlib").Path(cmd[cmd.index("-o") + 1]); cf.write_text('{"c":1}\n')
            return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        self._run_nuclei(tmp_path, monkeypatch, ok)           # run 1: 3 clean chunks -> valid state
        state = _json.loads((nucdir / "chunks.state.json").read_text())
        assert set(state["chunks"]) == {"0", "1", "2"}
        # CORRUPT the state: chunk 0 -> a missing file; chunk 1 -> a path-traversal escape; add a malformed key.
        (nucdir / state["chunks"]["0"]).unlink()              # chunk 0's artifact now MISSING
        state["chunks"]["1"] = "../../../../etc/passwd"       # out-of-tree
        state["chunks"]["x"] = "wu_/attempt_/findings_x.jsonl"   # malformed index key
        state["evidence"] = dict(state["chunks"])
        (nucdir / "chunks.state.json").write_text(_json.dumps(state))

        seen = []
        def track(tool, cmd, timeout=None, **k):
            seen.append(__import__("pathlib").Path(cmd[cmd.index("-o") + 1]).name)
            cf = __import__("pathlib").Path(cmd[cmd.index("-o") + 1]); cf.write_text('{"re":1}\n')
            return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        r2 = self._run_nuclei(tmp_path, monkeypatch, track)   # must not crash on the malformed key / traversal
        assert r2.status == Status.SUCCESS
        assert sorted(seen) == ["findings_0.jsonl", "findings_1.jsonl"]   # 0 (missing) + 1 (out-of-tree) re-ran; 2 kept
        assert (nucdir / "findings.jsonl").read_text().count("{") == 3     # aggregate reproducible (2 re-run + 1 kept)

    def test_partial_then_failed_retry_keeps_earlier_evidence(self, tmp_path, monkeypatch):
        # review#2: attempt 1 chunk 1 is PARTIAL WITH output; attempt 2 chunk 1 COMPLETES as FAILED with NO
        # artifact. The rebuilt aggregate must STILL contain attempt-1's degraded findings (evidence history is
        # separate from completion), not silently drop them.
        import json as _json
        from quarry_recon.runner import RunResult, Status
        cfgdir = tmp_path / "nuclei-cfg"; cfgdir.mkdir()
        (cfgdir / ".templates-config.json").write_text(_json.dumps({"nuclei-templates-version": "vX"}))
        monkeypatch.setenv("NUCLEI_CONFIG", str(cfgdir))
        nucdir = tmp_path / "raw" / "params" / "nuclei"

        # [145]: nonzero exit = execution INCOMPLETE, which is what keeps chunk 1 retryable across attempts
        def partial(tool, cmd, timeout=None, **k):
            cf = __import__("pathlib").Path(cmd[cmd.index("-o") + 1])
            if "findings_1." in cf.name:
                cf.write_text('{"deg":1}\n'); return RunResult("nuclei", cmd, Status.PARTIAL, 2, 0.1, cf, 1)
            cf.write_text('{"clean":1}\n'); return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        r1 = self._run_nuclei(tmp_path, monkeypatch, partial)
        assert r1.status == Status.PARTIAL
        assert (nucdir / "findings.jsonl").read_text().count('{"deg":1}') == 1   # attempt-1 degraded finding present

        def failed_no_output(tool, cmd, timeout=None, **k):   # attempt 2: chunk 1 FAILS, writes NOTHING
            return RunResult("nuclei", cmd, Status.FAILED, 1, 0.1, None, 0)
        r2 = self._run_nuclei(tmp_path, monkeypatch, failed_no_output)
        assert r2.status == Status.PARTIAL                    # chunk 1 still degraded/retryable
        # the aggregate must NOT have lost attempt-1's degraded finding to attempt-2's empty FAILED result
        agg = (nucdir / "findings.jsonl").read_text()
        assert agg.count('{"deg":1}') == 1 and agg.count('{"clean":1}') == 2

    def test_partial_then_partial_unions_both_attempts_evidence(self, tmp_path, monkeypatch):
        # review#1: PARTIAL(A) then PARTIAL(B) for the same chunk must keep findings from BOTH attempts
        # (evidence is a LIST, aggregated + deduped), not just the latest.
        import json as _json
        from quarry_recon.runner import RunResult, Status
        cfgdir = tmp_path / "nuclei-cfg"; cfgdir.mkdir()
        (cfgdir / ".templates-config.json").write_text(_json.dumps({"nuclei-templates-version": "vX"}))
        monkeypatch.setenv("NUCLEI_CONFIG", str(cfgdir))
        nucdir = tmp_path / "raw" / "params" / "nuclei"

        # [145]: an INCOMPLETE execution (nonzero exit) is what leaves a chunk retryable across attempts
        def partial_a(tool, cmd, timeout=None, **k):
            cf = __import__("pathlib").Path(cmd[cmd.index("-o") + 1])
            if "findings_1." in cf.name:
                cf.write_text('{"f1":1}\n{"f2":1}\n'); return RunResult("nuclei", cmd, Status.PARTIAL, 2, 0.1, cf, 2)
            cf.write_text('{"clean":1}\n'); return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        self._run_nuclei(tmp_path, monkeypatch, partial_a)

        def partial_b(tool, cmd, timeout=None, **k):          # attempt 2: chunk 1 re-run, overlapping + new finding
            cf = __import__("pathlib").Path(cmd[cmd.index("-o") + 1])
            cf.write_text('{"f2":1}\n{"f3":1}\n'); return RunResult("nuclei", cmd, Status.PARTIAL, 2, 0.1, cf, 2)
        self._run_nuclei(tmp_path, monkeypatch, partial_b)
        agg = (nucdir / "findings.jsonl").read_text()
        # both attempts' distinct findings kept, the overlapping one deduped ONCE
        assert agg.count('{"f1":1}') == 1 and agg.count('{"f2":1}') == 1 and agg.count('{"f3":1}') == 1

    def test_resume_rejects_cross_work_unit_artifact(self, tmp_path, monkeypatch):
        # review#2: a recorded path that is readable + correctly named but lives under a DIFFERENT work_unit dir
        # must be rejected (containment is under the CURRENT wu_<scan_wu>/, not just the nuclei dir) -> re-run,
        # never a false skip borrowing another work unit's artifact.
        import json as _json
        from quarry_recon.runner import RunResult, Status
        cfgdir = tmp_path / "nuclei-cfg"; cfgdir.mkdir()
        (cfgdir / ".templates-config.json").write_text(_json.dumps({"nuclei-templates-version": "vX"}))
        monkeypatch.setenv("NUCLEI_CONFIG", str(cfgdir))
        nucdir = tmp_path / "raw" / "params" / "nuclei"

        def ok(tool, cmd, timeout=None, **k):
            cf = __import__("pathlib").Path(cmd[cmd.index("-o") + 1]); cf.write_text('{"c":1}\n')
            return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        self._run_nuclei(tmp_path, monkeypatch, ok)           # run 1 -> valid state under wu_<scan_wu>
        state = _json.loads((nucdir / "chunks.state.json").read_text())
        # plant a FOREIGN work unit's artifact (readable, correctly named) and point chunk 0 at it
        foreign = nucdir / "wu_foreignunit" / "attempt_z" / "findings_0.jsonl"
        foreign.parent.mkdir(parents=True, exist_ok=True); foreign.write_text('{"foreign":1}\n')
        state["chunks"]["0"] = "wu_foreignunit/attempt_z/findings_0.jsonl"
        state["evidence"]["0"] = ["wu_foreignunit/attempt_z/findings_0.jsonl"]
        (nucdir / "chunks.state.json").write_text(_json.dumps(state))

        seen = []
        def track(tool, cmd, timeout=None, **k):
            seen.append(__import__("pathlib").Path(cmd[cmd.index("-o") + 1]).name)
            cf = __import__("pathlib").Path(cmd[cmd.index("-o") + 1]); cf.write_text('{"own":1}\n')
            return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        self._run_nuclei(tmp_path, monkeypatch, track)
        assert "findings_0.jsonl" in seen                     # chunk 0 RE-RAN (foreign entry rejected)
        agg = (nucdir / "findings.jsonl").read_text()
        assert '{"foreign":1}' not in agg and agg.count('{"own":1}') == 1   # never borrowed the foreign artifact

    @pytest.mark.parametrize("blob", ["[]", "null", '"text"', "1"])
    def test_non_object_state_reruns_all_without_crashing(self, tmp_path, monkeypatch, blob):
        # review#7: a syntactically valid but NON-OBJECT state ([], null, scalar) must be rejected (rerun all),
        # never crash on prev.get(...).
        from quarry_recon.runner import RunResult, Status
        nucdir = tmp_path / "raw" / "params" / "nuclei"; nucdir.mkdir(parents=True)
        (nucdir / "chunks.state.json").write_text(blob)

        seen = []
        def ok(tool, cmd, timeout=None, **k):
            seen.append(1)
            cf = __import__("pathlib").Path(cmd[cmd.index("-o") + 1]); cf.write_text('{"c":1}\n')
            return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
        r = self._run_nuclei(tmp_path, monkeypatch, ok)       # 5 hosts / chunk 2 -> 3 batches
        assert r.status == Status.SUCCESS and len(seen) == 3  # every chunk ran; no crash

    def test_ledger_is_own_event_not_second_terminal(self, tmp_path, monkeypatch):
        # dalfox emits a ledger — it must be a LEDGER event, so the source keeps exactly one tool_finish
        from quarry_recon import events, settings
        from types import SimpleNamespace
        from quarry_recon.runner import RunResult, Status
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(settings, "concurrency", lambda k, d=None: 2 if k == "DALFOX_CHUNK" else d)
        monkeypatch.setattr(settings, "workers", lambda t, d: d)

        def ok(tool, cmd, timeout=None, **k):
            return RunResult("dalfox", cmd, Status.SUCCESS, 0, 0.1, None, 0)
        monkeypatch.setattr(params, "exec_tool", ok)
        import quarry_recon.secrets as sec
        monkeypatch.setattr(sec, "oob", lambda: {})
        ctx = _Ctx(tmp_path)
        params._dalfox_xss_fast(ctx, [f"https://h/{i}?q=1" for i in range(3)], SimpleNamespace(http_rl=0))
        evs = self._events(tmp_path)
        ledgers = [e for e in evs if e["event"] == "ledger"]
        source_terminals = [e for e in evs if e["event"] == "tool_finish"
                            and e.get("work_unit") and e["work_unit"] not in
                            {ev["work_unit"] for ev in evs if ev["event"] == "tool_start" and ev.get("input_total")}]
        assert len(ledgers) == 1 and ledgers[0].get("produced")   # ledger is its own event with counts
        assert all(e["event"] != "tool_finish" or "ledger" not in e for e in evs)   # no tool_finish tagged ledger
