"""C07 authoritative contracts (first increment) — run_contract emits a stable source-id + a guaranteed
terminal event, applies the file-output reclassify so the terminal status is FINAL, and fails loud on an
unknown source. Migrated lanes route through it.
"""
import json

import pytest

from quarry_recon import contract, events
from quarry_recon.runner import RunResult, Status

pytestmark = pytest.mark.offline


@pytest.fixture(autouse=True)
def _capture_events(tmp_path):
    events.configure(tmp_path)
    yield
    events.reset()


def _events(tmp_path):
    p = tmp_path / "events.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def _patch_run(monkeypatch, fn):
    monkeypatch.setattr(contract, "_run", fn)


class TestTerminalEventGuarantee:
    def test_start_and_finish_emitted(self, tmp_path, monkeypatch):
        _patch_run(monkeypatch, lambda tool, cmd, **k: RunResult(tool, cmd, Status.SUCCESS, 0, 0.1, None, 3))
        contract.run_contract("vertical.subfinder", ["subfinder"])
        evs = [e["event"] for e in _events(tmp_path)]
        assert "tool_start" in evs and "tool_finish" in evs

    def test_terminal_event_fires_even_when_run_raises(self, tmp_path, monkeypatch):
        def boom(tool, cmd, **k):
            raise RuntimeError("tool blew up")
        _patch_run(monkeypatch, boom)
        with pytest.raises(RuntimeError):
            contract.run_contract("vertical.subfinder", ["subfinder"])
        fin = [e for e in _events(tmp_path) if e["event"] == "tool_finish"]
        assert len(fin) == 1 and fin[0]["status"] == "failed"      # synthetic terminal on exception

    def test_reclassify_sets_final_status_on_terminal(self, tmp_path, monkeypatch):
        # run() returns EMPTY; reclassify promotes to SUCCESS → the terminal event must carry SUCCESS
        _patch_run(monkeypatch, lambda tool, cmd, **k: RunResult(tool, cmd, Status.EMPTY, 0, 0.1, None, 0))

        def reclassify(res):
            res.status = Status.SUCCESS
            return res
        contract.run_contract("crawl.gitleaks", ["gitleaks"], reclassify=reclassify)
        fin = [e for e in _events(tmp_path) if e["event"] == "tool_finish"][0]
        assert fin["status"] == "success"

    def test_blocked_emits_dedicated_event(self, tmp_path, monkeypatch):
        _patch_run(monkeypatch, lambda tool, cmd, **k: RunResult(tool, cmd, Status.BLOCKED, 0, 0.1, None, 0,
                                                                 note="WAF"))
        contract.run_contract("vertical.subfinder", ["subfinder"])
        assert any(e["event"] == "tool_blocked" for e in _events(tmp_path))


class TestUnknownSourceFailsLoud:
    def test_unknown_source_not_executed(self, tmp_path, monkeypatch):
        called = []
        _patch_run(monkeypatch, lambda *a, **k: called.append(1))
        res = contract.run_contract("not.a.real.source", ["x"])
        assert res.status == Status.SKIPPED and not called          # command never handed to runner.run
        assert any(e["event"] == "tool_blocked" for e in _events(tmp_path))

    def test_returns_reclassified_result(self, tmp_path, monkeypatch):
        _patch_run(monkeypatch, lambda tool, cmd, **k: RunResult(tool, cmd, Status.EMPTY, 0, 0.1, None, 0))
        out = contract.run_contract("vertical.subfinder", ["subfinder"],
                                    reclassify=lambda r: (setattr(r, "status", Status.SUCCESS), r)[1])
        assert out.status == Status.SUCCESS


class TestRunProvider:
    """C07 inc5 — in-process HTTP providers get a source lifecycle bracket (tool_start/tool_finish),
    without run_contract (they are native urllib, not a subprocess)."""

    def test_start_and_finish_bracketed(self, tmp_path):
        from quarry_recon.contract import run_provider
        res = run_provider("vertical.crtsh", lambda: {"a.example.com", "b.example.com"})
        assert res == {"a.example.com", "b.example.com"}
        evs = [e["event"] for e in _events(tmp_path)]
        assert "tool_start" in evs and "tool_finish" in evs

    def test_result_returned_unchanged(self, tmp_path):
        from quarry_recon.contract import run_provider
        assert run_provider("vertical.crtsh", lambda: {"x"}) == {"x"}

    def test_empty_result_is_empty_status(self, tmp_path):
        from quarry_recon.contract import run_provider
        run_provider("vertical.crtsh", lambda: set())
        fin = [e for e in _events(tmp_path) if e["event"] == "tool_finish"][0]
        assert fin["status"] == "empty"

    def test_nonempty_result_is_success_with_produced(self, tmp_path):
        from quarry_recon.contract import run_provider
        run_provider("vertical.certspotter", lambda: {"a", "b", "c"})
        fin = [e for e in _events(tmp_path) if e["event"] == "tool_finish"][0]
        assert fin["status"] == "success" and fin["produced"] == {"host": 3}

    def test_terminal_fires_even_if_provider_raises(self, tmp_path):
        from quarry_recon.contract import run_provider
        def boom():
            raise RuntimeError("http died")
        with pytest.raises(RuntimeError):
            run_provider("vertical.crtsh", boom)
        fin = [e for e in _events(tmp_path) if e["event"] == "tool_finish"]
        assert len(fin) == 1 and fin[0]["status"] == "failed"

    def test_unknown_source_still_runs_but_blocked_emitted(self, tmp_path):
        from quarry_recon.contract import run_provider
        assert run_provider("not.a.provider", lambda: {"x"}) == {"x"}   # coverage not lost to a registry typo
        assert any(e["event"] == "tool_blocked" for e in _events(tmp_path))


class TestLanesMigrated:
    # increment 1+2 (single-shot) + increment 3 (work-unit'd looped/grouped lanes)
    MIGRATED = [
        ("quarry_recon.phases.vertical", "vertical.subfinder"),
        ("quarry_recon.phases.vertical", "vertical.shosubgo"),
        ("quarry_recon.phases.crawl", "crawl.gitleaks"),
        ("quarry_recon.phases.probe", "probe.tlsx_certs"),
        ("quarry_recon.phases.probe", "probe.gowitness"),
        ("quarry_recon.phases.crawl", "crawl.katana_standard"),
        ("quarry_recon.phases.crawl", "crawl.katana_headless"),
        ("quarry_recon.phases.crawl", "crawl.gau"),
        ("quarry_recon.phases.probe", "probe.ffuf_vhost"),
        ("quarry_recon.phases.content", "content.ffuf"),
        ("quarry_recon.phases.probe", "probe.nmap_service"),
    ]
    # dynamic-source_id lanes (f-string / variable) — source_id can't be literal-grepped
    DYNAMIC = [
        ("quarry_recon.phases.probe", "probe.httpx"),               # run_contract(f"{phase}.httpx", ...)
        ("quarry_recon.phases.crawl", "crawl.waymore_urls"),        # run_contract(sid, ...) via mode
    ]
    # lanes that must key events on a stable work_unit (looped/grouped — the C10b resume key)
    WORKUNIT_MODULES = ["quarry_recon.phases.probe", "quarry_recon.phases.content"]

    @pytest.mark.parametrize("module,sid", MIGRATED)
    def test_lane_uses_run_contract(self, module, sid):
        import importlib
        import inspect
        src = inspect.getsource(importlib.import_module(module))
        assert f'run_contract("{sid}"' in src

    @pytest.mark.parametrize("module", WORKUNIT_MODULES)
    def test_grouped_lanes_pass_work_unit(self, module):
        import importlib
        import inspect
        src = inspect.getsource(importlib.import_module(module))
        assert "events.work_unit(" in src and "work_unit=wu" in src   # a stable resume key is computed + passed

    @pytest.mark.parametrize("sid", [m[1] for m in MIGRATED] + [d[1] for d in DYNAMIC])
    def test_migrated_source_ids_are_registered(self, sid):
        from quarry_recon import sources
        assert sources.get(sid) is not None                         # contract would else fail loud
