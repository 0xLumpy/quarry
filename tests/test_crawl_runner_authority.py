"""Focused crawl callers at the Phase 1 runner ownership boundary."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from quarry_recon import events, store
from quarry_recon.phases import crawl
from quarry_recon.runner_repository import ArtifactDisposition, RepositoryOutput


pytestmark = pytest.mark.offline


def _running_context(tmp_path):
    run = store.Run.create(tmp_path, "acme.example", run_id="crawl-runner-authority")
    run.write_state("running")
    return SimpleNamespace(run=run, http_timeout=10)


def test_jsluice_retains_unique_chunks_and_claim_publishes_the_aggregate(
    tmp_path, monkeypatch,
):
    ctx = _running_context(tmp_path)
    files = []
    for index in range(2):
        source = tmp_path / f"input-{index}.js"
        source.write_text(f"const value = {index};\n")
        files.append(source)
    aggregate = ctx.run.raw_path("crawl", "jsluice", "urls.jsonl")
    payloads = [b'{"url":"/one"}\n', b'{"url":"/two"}\n']
    calls = []

    def fake_exec(tool, cmd, **kwargs):
        assert kwargs["repository"] is ctx.run
        output = kwargs["stdout"]
        assert type(output) is RepositoryOutput
        assert output.disposition is ArtifactDisposition.PUBLISH
        payload = payloads[len(calls)]
        path = ctx.run._replace_artifact(
            store.MutationScope.BASE_EVIDENCE, output.components, payload,
        )
        calls.append(path)
        return SimpleNamespace(
            tool=tool, cmd=cmd, status=crawl.Status.SUCCESS, raw_path=path,
            duration=0.01, exit_code=0, note="", stderr_tail="", stdout_lines=1,
        )

    monkeypatch.setattr(crawl, "exec_tool", fake_exec)
    events.reset()
    try:
        events.configure(ctx.run)
        text, status = crawl._jsluice_run(ctx, "urls", files, aggregate, "js")
    finally:
        events.reset()

    assert status is crawl.Status.SUCCESS
    assert text.encode() == b"".join(payloads)
    assert aggregate.read_bytes() == b"".join(payloads)
    assert len(calls) == 2 and len(set(calls)) == 2
    assert all(path.is_file() for path in calls), "chunk artifacts are authoritative evidence"
    assert not list(aggregate.parent.glob("*.part"))


def test_beautify_publishes_stdout_to_the_outer_generation_and_discards_stderr(
    tmp_path, monkeypatch,
):
    ctx = _running_context(tmp_path)
    generation = ctx.run.raw_path("crawl", "js", "derived.gen-test")
    generation.mkdir(parents=True)
    source = generation / "app.js"
    source.write_text("const x=1;\n")
    seen = []

    def fake_exec(tool, cmd, **kwargs):
        seen.append(kwargs)
        output = kwargs["stdout"]
        path = ctx.run._replace_artifact(
            store.MutationScope.BASE_EVIDENCE,
            output.components,
            b"const x = 1;\n",
        )
        return SimpleNamespace(
            tool=tool, cmd=cmd, status=crawl.Status.SUCCESS, raw_path=path,
            duration=0.01, exit_code=0, note="", stderr_tail="", stdout_lines=0,
            cpu_s=0.0, peak_rss_mb=0.0, meta={},
        )

    monkeypatch.setattr(crawl, "exec_tool", fake_exec)
    events.reset()
    try:
        events.configure(ctx.run)
        ok, degraded, status = crawl._beautify_run(ctx, [source])
    finally:
        events.reset()

    assert (ok, degraded, status) == (1, 0, crawl.Status.SUCCESS)
    assert len(seen) == 1 and seen[0]["repository"] is ctx.run
    assert seen[0]["stdout"] == RepositoryOutput.publish(
        *source.with_suffix(".js.beauty").relative_to(ctx.run.dir).parts,
    )
    assert seen[0]["stderr"] == RepositoryOutput.discard()
    assert source.read_text() == "const x = 1;\n"


def test_beautify_return_boundary_cannot_replace_source_after_base_seal(
    tmp_path, monkeypatch,
):
    ctx = _running_context(tmp_path)
    source = ctx.run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "crawl", "js", "derived.gen-test", "app.js"),
        b"const original = true;\n",
    )
    seal_state = []

    def fake_exec(tool, cmd, **kwargs):
        output = kwargs["stdout"]
        path = ctx.run._replace_artifact(
            store.MutationScope.BASE_EVIDENCE,
            output.components,
            b"const beautified = true;\n",
        )
        try:
            ctx.run.begin_finalization()
        except store.ContractError:
            seal_state.append("blocked-by-claim")
        else:
            seal_state.append(ctx.run.state)
        return SimpleNamespace(
            tool=tool, cmd=cmd, status=crawl.Status.SUCCESS, raw_path=path,
            duration=0.01, exit_code=0, note="", stderr_tail="", stdout_lines=0,
            cpu_s=0.0, peak_rss_mb=0.0, meta={},
        )

    monkeypatch.setattr(crawl, "exec_tool", fake_exec)
    monkeypatch.setattr(crawl.events, "tool_start", lambda *a, **k: None)
    monkeypatch.setattr(crawl.events, "tool_progress", lambda *a, **k: None)
    monkeypatch.setattr(crawl.events, "tool_finish", lambda *a, **k: None)
    monkeypatch.setattr(store.Run, "record", lambda *a, **k: None)

    _ok, degraded, status = crawl._beautify_run(ctx, [source])

    assert seal_state in (["blocked-by-claim"], ["finalizing"])
    if ctx.run.state == "finalizing":
        assert source.read_bytes() == b"const original = true;\n"
        assert degraded == 1
        assert status is crawl.Status.PARTIAL
    else:
        assert seal_state == ["blocked-by-claim"]
        assert source.read_bytes() == b"const beautified = true;\n"
        assert degraded == 0
        assert status is crawl.Status.SUCCESS


def test_js_derived_generation_cannot_publish_after_base_seal(
    tmp_path, monkeypatch,
):
    ctx = _running_context(tmp_path)
    source = ctx.run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "crawl", "js-fetch", "bodies", "app.js"),
        b"const original = true;\n",
    )
    raw_dir = source.parent
    active = raw_dir.parent / "js_derived"
    real_publish_tree = crawl._publish_tree

    def seal_then_publish(inner_ctx, destination, staging):
        # Make the ambient generation admissible to the durability walk so this
        # exercises the publication-vs-seal boundary, not loose default modes.
        os.chmod(staging, 0o700)
        for path in staging.rglob("*"):
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
        try:
            inner_ctx.run.begin_finalization()
        except store.ContractError:
            pass
        return real_publish_tree(inner_ctx, destination, staging)

    monkeypatch.setattr(crawl, "have", lambda _tool: False)
    monkeypatch.setattr(crawl, "_js_mineable", lambda *a, **k: None)
    monkeypatch.setattr(crawl, "_publish_tree", seal_then_publish)
    ledger = SimpleNamespace(artifacts=lambda: [source])

    published = crawl._js_publish_derived(ctx, ledger, raw_dir)

    if ctx.run.state == "finalizing":
        assert published is None
        assert not active.exists()
    else:
        assert ctx.run.state == "running"
        assert published == active
        assert active.is_dir()
