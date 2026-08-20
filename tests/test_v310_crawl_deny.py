"""v0.3.10 crawl closure: unsupported sandboxes refuse before a child launch."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from quarry_recon import events, store
from quarry_recon.phases import crawl
from quarry_recon.runner import RunResult, Status


pytestmark = pytest.mark.offline


def _run(tmp_path):
    run = store.Run.create(tmp_path, "acme.com")
    run._network_policy_scope = object()
    return run


def _ledger(artifact):
    return SimpleNamespace(items=lambda: iter([("https://acme.com/app.js", artifact)]))


def test_bound_jxscout_chunks_records_refusal_without_subprocess(tmp_path, monkeypatch):
    run = _run(tmp_path)
    artifact = tmp_path / "app.js"
    artifact.write_text("x")
    ctx = SimpleNamespace(
        run=run, profile=SimpleNamespace(js_chunk_brute=0),
        scope=SimpleNamespace(in_scope=lambda _host: True), echo=lambda *_args: None,
    )
    monkeypatch.setattr(crawl, "have", lambda _tool: pytest.fail("capability check reached launch path"))
    monkeypatch.setattr(crawl, "run_contract", lambda *a, **k: pytest.fail("subprocess launched"))

    assert crawl._jxscout_chunks(ctx, _ledger(artifact)) == 0
    record = run._tool_runs[-1]
    assert record.tool == crawl.JXSCOUT_SHIM and record.status == Status.SKIPPED.value
    assert "v0.3.10" in record.note and "no analyzer subprocess" in record.note


def test_bound_jxscout_ast_records_refusal_before_cgroup_cleanup(tmp_path, monkeypatch):
    run = _run(tmp_path)
    artifact = tmp_path / "app.js"
    artifact.write_text("x")
    ctx = SimpleNamespace(run=run, scope=SimpleNamespace(in_scope=lambda _host: True),
                          echo=lambda *_args: None, profile=SimpleNamespace())
    monkeypatch.setattr(crawl.cgroup, "clear", lambda _unit: pytest.fail("cgroup cleanup reached"))
    monkeypatch.setattr(crawl, "run_contract", lambda *a, **k: pytest.fail("subprocess launched"))

    assert crawl._ast_bundles(ctx, _ledger(artifact)) == 0
    record = run._tool_runs[-1]
    assert record.tool == crawl.AST_SHIM and record.status == Status.SKIPPED.value
    assert "v0.3.10" in record.note and "no analyzer subprocess" in record.note


def test_trufflehog_always_uses_offline_argv_and_notes_refused_verification(tmp_path, monkeypatch):
    run = store.Run.create(tmp_path, "acme.com")
    derived = tmp_path / "derived"
    derived.mkdir()
    (derived / "app.js").write_text("x")
    seen = []

    def write_list(name, values):
        path = run.dir / name
        path.write_text("\n".join(values) + ("\n" if values else ""))
        return path

    def fake_exec(tool, cmd, **_kwargs):
        seen.append(cmd)
        return RunResult(tool, cmd, Status.SUCCESS, 0, 0.0, None, 0)

    def fake_contract(tool, cmd, **_kwargs):
        return RunResult(tool, cmd, Status.SKIPPED, None, 0.0, None, 0,
                         note="not needed in this focused lane test")

    profile = SimpleNamespace(
        apex_domains=["acme.com"], headless=False, http_rl=None,
        verify_secrets=True, waymore_limit=1,
    )
    scope = SimpleNamespace(passive_only=True, in_scope=lambda _host: True, is_oos=lambda _host: False)
    ctx = SimpleNamespace(
        run=run, profile=profile, scope=scope, http_timeout=1, write_list=write_list,
        echo=lambda *_args: None,
    )
    monkeypatch.setattr(crawl, "have", lambda tool: tool == "trufflehog")
    monkeypatch.setattr(crawl, "exec_tool", fake_exec)
    monkeypatch.setattr(crawl, "run_contract", fake_contract)
    monkeypatch.setattr(crawl, "_js_download", lambda _ctx: (None, None))
    monkeypatch.setattr(crawl, "_jxscout_traverse", lambda _ctx, ledger, raw: (ledger, raw))
    monkeypatch.setattr(crawl, "_js_publish_derived", lambda _ctx, _ledger, _raw: derived)
    monkeypatch.setattr(crawl, "_sourcemap_recover", lambda _ctx, _ledger: None)
    monkeypatch.setattr(crawl, "_xnl_lane", lambda *_args: None)
    monkeypatch.setattr(crawl, "_ast_bundles", lambda *_args: 0)

    events.configure(run.dir)
    try:
        crawl.run(ctx)
    finally:
        events.reset()

    assert len(seen) == 1
    assert "--no-update" in seen[0] and "--no-verification" in seen[0]
    record = next(row for row in run._tool_runs if row.tool == "trufflehog")
    assert "v0.3.10" in record.note and "verification" in record.note
