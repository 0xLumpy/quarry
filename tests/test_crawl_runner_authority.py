"""Focused crawl callers at the Phase 1 runner ownership boundary."""
from __future__ import annotations

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
