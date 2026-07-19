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


class TestLanesMigrated:
    @pytest.mark.parametrize("module,sid", [
        ("quarry_recon.phases.vertical", '"vertical.subfinder"'),
        ("quarry_recon.phases.vertical", '"vertical.shosubgo"'),
        ("quarry_recon.phases.crawl", '"crawl.gitleaks"'),
    ])
    def test_lane_uses_run_contract(self, module, sid):
        import importlib
        import inspect
        src = inspect.getsource(importlib.import_module(module))
        assert f"run_contract({sid}" in src

    @pytest.mark.parametrize("sid", ["vertical.subfinder", "vertical.shosubgo", "crawl.gitleaks"])
    def test_migrated_source_ids_are_registered(self, sid):
        from quarry_recon import sources
        assert sources.get(sid) is not None                         # contract would else fail loud
