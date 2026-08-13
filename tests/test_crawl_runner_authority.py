"""Focused crawl callers at the Phase 1 runner ownership boundary."""
from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest

from quarry_recon import events, runner_native, store
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


def test_beautify_retains_stdout_then_copies_it_into_the_owned_tree(
    tmp_path, monkeypatch,
):
    ctx = _running_context(tmp_path)
    source = ctx.run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "crawl", "js-fetch", "bodies", "app.js"),
        b"const x=1;\n",
    )
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
    monkeypatch.setattr(crawl, "have", lambda tool: tool == "js-beautify")
    monkeypatch.setattr(crawl, "_js_mineable", lambda *a, **k: None)
    events.reset()
    try:
        events.configure(ctx.run)
        published = crawl._js_publish_derived(
            ctx, SimpleNamespace(artifacts=lambda: [source]), source.parent,
        )
    finally:
        events.reset()

    assert published is not None
    assert len(seen) == 1 and seen[0]["repository"] is ctx.run
    assert seen[0]["stdout"].components[:3] == ("raw", "crawl", "js-beautify")
    assert seen[0]["stderr"] == RepositoryOutput.discard()
    assert (published / "app.js").read_text() == "const x = 1;\n"
    assert source.read_text() == "const x=1;\n"
    assert ctx.run._live_artifact_claim_count() == 0


def test_beautify_return_boundary_remains_behind_outer_tree_claim(
    tmp_path, monkeypatch,
):
    ctx = _running_context(tmp_path)
    source = ctx.run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "crawl", "js-fetch", "bodies", "app.js"),
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
    monkeypatch.setattr(crawl, "have", lambda tool: tool == "js-beautify")
    monkeypatch.setattr(crawl, "_js_mineable", lambda *a, **k: None)

    published = crawl._js_publish_derived(
        ctx, SimpleNamespace(artifacts=lambda: [source]), source.parent,
    )

    assert seal_state == ["blocked-by-claim"]
    assert ctx.run.state == "running"
    assert source.read_bytes() == b"const original = true;\n"
    assert (published / "app.js").read_bytes() == b"const beautified = true;\n"
    assert ctx.run._live_artifact_claim_count() == 0


def test_beautify_noncurrent_output_falls_back_to_repository_source(
    tmp_path, monkeypatch,
):
    ctx = _running_context(tmp_path)
    source = ctx.run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "crawl", "js-fetch", "bodies", "app.js"),
        b"const original = true;\n",
    )
    stale = b"const stale = true;\n"

    def fake_exec(tool, cmd, **kwargs):
        output = kwargs["stdout"]
        path = ctx.run._replace_artifact(
            store.MutationScope.BASE_EVIDENCE, output.components, stale,
        )
        return SimpleNamespace(
            tool=tool, cmd=cmd, status=crawl.Status.SUCCESS, raw_path=path,
            duration=0.01, exit_code=0, note="", stderr_tail="",
            stdout_lines=0, cpu_s=0.0, peak_rss_mb=0.0,
            meta={"native_outputs": {"current_paths": []}},
        )

    monkeypatch.setattr(crawl, "exec_tool", fake_exec)
    monkeypatch.setattr(crawl.events, "tool_start", lambda *a, **k: None)
    monkeypatch.setattr(crawl.events, "tool_progress", lambda *a, **k: None)
    monkeypatch.setattr(crawl.events, "tool_finish", lambda *a, **k: None)
    monkeypatch.setattr(crawl.events, "coverage_partial", lambda *a, **k: None)
    monkeypatch.setattr(crawl.events, "ledger", lambda *a, **k: None)
    monkeypatch.setattr(store.Run, "record", lambda *a, **k: None)
    monkeypatch.setattr(crawl, "have", lambda tool: tool == "js-beautify")
    monkeypatch.setattr(crawl, "_js_mineable", lambda *a, **k: None)

    published = crawl._js_publish_derived(
        ctx, SimpleNamespace(artifacts=lambda: [source]), source.parent,
    )

    assert published is not None
    assert (published / "app.js").read_bytes() == b"const original = true;\n"
    assert source.read_bytes() == b"const original = true;\n"
    assert ctx.run._live_artifact_claim_count() == 0


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
    real_digest = crawl._expected_tree_digest
    seal_state = []

    def seal_during_build(entries):
        try:
            ctx.run.begin_finalization()
        except store.ContractError:
            seal_state.append("blocked-by-claim")
        else:
            seal_state.append(ctx.run.state)
        return real_digest(entries)

    monkeypatch.setattr(crawl, "have", lambda _tool: False)
    monkeypatch.setattr(crawl, "_js_mineable", lambda *a, **k: None)
    monkeypatch.setattr(crawl, "_expected_tree_digest", seal_during_build)
    ledger = SimpleNamespace(artifacts=lambda: [source])

    published = crawl._js_publish_derived(ctx, ledger, raw_dir)

    assert seal_state == ["blocked-by-claim"]
    assert ctx.run.state == "running"
    assert published == active
    assert active.is_dir()
    assert ctx.run._live_artifact_claim_count() == 0


def test_sourcemap_tree_and_candidates_publish_under_outer_claim(
    tmp_path, monkeypatch,
):
    ctx = _running_context(tmp_path)
    ctx.scope = SimpleNamespace(active_allowed=lambda _host: True)
    ctx.echo = lambda _message: None
    payload = json.dumps({
        "version": 3,
        "sources": ["src/app.ts"],
        "sourcesContent": ["const owned = true;"],
    }).encode()
    inline = base64.b64encode(payload).decode()
    source = ctx.run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "crawl", "js-fetch", "bodies", "inline.js"),
        f"//# sourceMappingURL=data:application/json;base64,{inline}\n".encode(),
    )
    ledger = SimpleNamespace(items=lambda: [("https://acme.example/inline.js", source)])
    seal_state = []
    real_extract = crawl._extract_payload

    def extract_during_seal(text, key, builder, tally):
        result = real_extract(text, key, builder, tally)
        try:
            ctx.run.begin_finalization()
        except store.ContractError:
            seal_state.append("blocked-by-claim")
        else:
            seal_state.append(ctx.run.state)
        return result

    monkeypatch.setattr(crawl, "_extract_payload", extract_during_seal)
    events.reset()
    try:
        events.configure(ctx.run)
        published = crawl._sourcemap_recover(ctx, ledger)
    finally:
        events.reset()

    assert seal_state == ["blocked-by-claim"]
    assert published is not None
    recovered = [path for path in published.rglob("*") if path.is_file()]
    assert len(recovered) == 1
    assert recovered[0].read_text() == "const owned = true;"
    candidates = ctx.run.dir / "raw" / "crawl" / "sourcemaps" / "candidates.txt"
    assert candidates.read_text() == "https://acme.example/inline.js.map\n"
    assert ctx.run.state == "running"
    assert ctx.run._live_artifact_claim_count() == 0


def test_js_tree_cancellation_fences_stage_and_preserves_prior(
    tmp_path, monkeypatch,
):
    ctx = _running_context(tmp_path)
    source = ctx.run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "crawl", "js-fetch", "bodies", "first.js"),
        b"const prior = true;\n",
    )
    monkeypatch.setattr(crawl, "have", lambda _tool: False)
    monkeypatch.setattr(crawl, "_js_mineable", lambda *a, **k: None)
    active = crawl._js_publish_derived(
        ctx, SimpleNamespace(artifacts=lambda: [source]), source.parent,
    )
    assert active is not None
    prior = (active / "first.js").read_bytes()

    replacement = ctx.run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "crawl", "js-fetch", "bodies", "second.js"),
        b"const replacement = true;\n",
    )
    cancellation = KeyboardInterrupt("cancel derived tree")

    real_copy = runner_native.NativeTreeBuilder.copy_repository_file

    def cancel_after_copy(builder, *args, **kwargs):
        real_copy(builder, *args, **kwargs)
        raise cancellation

    monkeypatch.setattr(
        runner_native.NativeTreeBuilder,
        "copy_repository_file",
        cancel_after_copy,
    )
    with pytest.raises(KeyboardInterrupt) as raised:
        crawl._js_publish_derived(
            ctx, SimpleNamespace(artifacts=lambda: [replacement]), replacement.parent,
        )

    assert raised.value is cancellation
    assert (active / "first.js").read_bytes() == prior
    assert not (active / "second.js").exists()
    assert ctx.run._live_artifact_claim_count() == 0
    stages = (
        ctx.run.project_dir / "recon" / "state" / "native-stages" / ctx.run.run_id
    )
    assert not stages.exists() or list(stages.iterdir()) == []
