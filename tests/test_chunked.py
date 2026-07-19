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
        assert 'prev.get("work_unit") == scan_wu' in src    # validity check keys on it
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
        finishes = [e for e in self._events(tmp_path) if e["event"] == "tool_finish"]
        # the SOURCE terminal (last finish) must be failed — status started FAILED, loop never reset it
        assert finishes[-1]["status"] == "failed"

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
