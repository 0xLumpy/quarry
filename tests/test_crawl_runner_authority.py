"""Focused crawl callers at the Phase 1 runner ownership boundary."""
from __future__ import annotations

import ast
import base64
import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import events, runner_native, store
from quarry_recon.phases import crawl
from quarry_recon.runner_repository import ArtifactDisposition, RepositoryOutput


pytestmark = pytest.mark.offline


EXPECTED_NATIVE_SINKS = {
    ("content", "_run_one", "content.ffuf", (16,)),
    ("crawl", "run", "crawl.katana_standard", (16,)),
    ("crawl", "run", "<dynamic>", (6, 13)),
    ("crawl", "run", "crawl.gitleaks", (4,)),
    ("crawl", "_xnl_run", "xnLinkFinder", (7, 9, 14, 16)),
    ("enrich", "run", "nuclei", (7,)),
    ("enrich", "run", "gowitness", (6, 9)),
    ("enrich", "run", "smap", (4,)),
    ("params", "_arjun_exec", "arjun", (4,)),
    ("params", "_nuclei_scan_lane", "nuclei", (5,)),
    ("params", "_dalfox_xss_fast", "dalfox", (6,)),
    ("params", "_takeover_nuclei_lane", "nuclei", (7,)),
    ("probe", "_vhost_scan", "probe.ffuf_vhost", (17,)),
    ("probe", "_cdn_shared_ips", "cdncheck", (7,)),
    ("probe", "_web_port_prefilter", "naabu", (11,)),
    ("probe", "run", "nuclei", (7,)),
    ("probe", "run", "probe.gowitness", (6, 9)),
    ("probe", "run", "probe.nmap_service", (9,)),
    ("probe", "run", "smap", (4,)),
    ("vertical", "_recursive_permute", "puredns", (6,)),
}


def _running_context(tmp_path):
    run = store.Run.create(tmp_path, "acme.example", run_id="crawl-runner-authority")
    run.write_state("running")
    return SimpleNamespace(run=run, http_timeout=10)


def _native_policy_indices(call: ast.Call, function: ast.FunctionDef) -> tuple[int, ...]:
    keyword = next(key for key in call.keywords if key.arg == "native_outputs")
    policy_nodes = [keyword.value]
    if isinstance(keyword.value, ast.Name):
        name = keyword.value.id
        policy_nodes = [
            node.value
            for node in ast.walk(function)
            if ((isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == name
                         for target in node.targets))
                or (isinstance(node, ast.AugAssign)
                    and isinstance(node.target, ast.Name)
                    and node.target.id == name))
        ]
    indices = set()
    for root in policy_nodes:
        for node in ast.walk(root):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "RepositoryNativeOutput"):
                continue
            if (node.func.attr == "file" and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and type(node.args[0].value) is int):
                indices.add(node.args[0].value)
            elif node.func.attr == "tree" and node.args:
                indices.update(
                    item.elts[0].value
                    for item in ast.walk(node.args[0])
                    if (isinstance(item, ast.Tuple) and len(item.elts) == 2
                        and isinstance(item.elts[0], ast.Constant)
                        and type(item.elts[0].value) is int)
                )
    return tuple(sorted(indices))


def test_native_output_sink_inventory_is_exact_and_static():
    """Every managed argv sink is a finite, reviewable production call site."""
    from quarry_recon import phases

    observed = set()
    for module_path in sorted(Path(phases.__file__).parent.glob("*.py")):
        if module_path.stem == "__init__":
            continue
        tree = ast.parse(module_path.read_text())

        class Visitor(ast.NodeVisitor):
            def __init__(self):
                self.functions = []

            def visit_FunctionDef(self, node):
                self.functions.append(node)
                self.generic_visit(node)
                self.functions.pop()

            def visit_Call(self, node):
                if any(key.arg == "native_outputs" for key in node.keywords):
                    tool = (
                        node.args[0].value
                        if node.args and isinstance(node.args[0], ast.Constant)
                        else "<dynamic>"
                    )
                    observed.add((
                        module_path.stem,
                        self.functions[-1].name,
                        tool,
                        _native_policy_indices(node, self.functions[-1]),
                    ))
                self.generic_visit(node)

        Visitor().visit(tree)

    assert observed == EXPECTED_NATIVE_SINKS


def test_crawl_has_no_ambient_canonical_native_sink_mutations():
    """The former Crawl bypasses stay absent at the source boundary."""
    source = inspect.getsource(crawl)
    materialize = inspect.getsource(crawl._xnl_materialize)
    blob = inspect.getsource(crawl._xnl_blob)
    outputs = inspect.getsource(crawl._xnl_outputs)
    assert "def _stage_dir(" not in source
    assert "def _publish_tree(" not in source
    assert "write_bytes" not in materialize and ".unlink(" not in materialize
    assert 'blob.open("wb")' not in blob
    assert ".raw_path(" not in blob and ".raw_path(" not in outputs
    assert "raw_dir.mkdir(parents=True, exist_ok=True)" not in source
    assert "map_dir.mkdir(parents=True, exist_ok=True)" not in source
    assert "cache_dir.mkdir(parents=True, exist_ok=True)" not in source


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


def test_xnl_blob_claim_blocks_seal_and_publishes_bounded_input(
    tmp_path, monkeypatch,
):
    ctx = _running_context(tmp_path)
    source = tmp_path / "xnl-input"
    source.mkdir()
    (source / "app.js").write_bytes(b"const endpoint = '/api';")
    seal_state = []
    real_write = crawl._repository_write_all

    def write_while_sealing(descriptor, data):
        if not seal_state:
            try:
                ctx.run.begin_finalization()
            except store.ContractError:
                seal_state.append("blocked-by-claim")
            else:
                seal_state.append(ctx.run.state)
        return real_write(descriptor, data)

    monkeypatch.setattr(crawl, "_repository_write_all", write_while_sealing)
    prep = crawl._xnl_blob(ctx, str(source), "js")

    assert seal_state == ["blocked-by-claim"]
    assert prep["digest"] and prep["written"] == prep["blob"].stat().st_size
    assert prep["blob"].read_bytes().startswith(b"\n")
    assert ctx.run.state == "running"
    assert ctx.run._live_artifact_claim_count() == 0


def test_xnl_blob_non_run_owner_fails_closed_before_managed_path_effect(tmp_path):
    source = tmp_path / "xnl-fake-owner-input"
    source.mkdir()
    (source / "app.js").write_bytes(b"const x = 1;")
    fake_root = tmp_path / "fake-run"
    ctx = SimpleNamespace(run=SimpleNamespace(dir=fake_root))

    prep = crawl._xnl_blob(ctx, str(source), "js")

    assert prep["written"] == 0 and prep["digest"] == ""
    assert not fake_root.exists()


def test_xnl_blob_cancellation_fences_stage_and_preserves_prior(
    tmp_path, monkeypatch,
):
    ctx = _running_context(tmp_path)
    components = ("raw", "crawl", "xnLinkFinder", "js_input.txt")
    prior = ctx.run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE, components, b"prior bounded input",
    )
    source = tmp_path / "xnl-cancel-input"
    source.mkdir()
    (source / "app.js").write_bytes(b"replacement")
    cancellation = KeyboardInterrupt("cancel XNL input publication")
    real_write = crawl._repository_write_all
    calls = 0

    def cancel_after_write(descriptor, data):
        nonlocal calls
        calls += 1
        real_write(descriptor, data)
        if calls == 2:
            raise cancellation

    monkeypatch.setattr(crawl, "_repository_write_all", cancel_after_write)
    with pytest.raises(KeyboardInterrupt) as raised:
        crawl._xnl_blob(ctx, str(source), "js")

    assert raised.value is cancellation
    assert prior.read_bytes() == b"prior bounded input"
    assert ctx.run._live_artifact_claim_count() == 0


def test_xnl_materialize_commits_present_and_absent_under_one_run_authority(
    tmp_path,
):
    ctx = _running_context(tmp_path)
    outs = crawl._xnl_outputs(ctx, "js")
    ctx.run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        tuple(outs["secrets"].relative_to(ctx.run.dir).parts),
        b"planted stale secret",
    )
    snapshot = {
        "links": ("ok", b"https://api.acme.example/x\n"),
        "params": ("ok", b"q\n"),
        "secrets": ("absent", b""),
        "wordlist": ("absent", b""),
    }

    crawl._xnl_materialize(ctx, "js", snapshot)

    assert outs["links"].read_bytes() == snapshot["links"][1]
    assert outs["params"].read_bytes() == snapshot["params"][1]
    assert not outs["secrets"].exists() and not outs["wordlist"].exists()
    assert ctx.run._live_artifact_claim_count() == 0


def test_xnl_snapshot_refuses_preserved_prior_without_current_receipt(tmp_path):
    ctx = _running_context(tmp_path)
    outs = crawl._xnl_outputs(ctx, "js")
    for key, path in outs.items():
        ctx.run._replace_artifact(
            store.MutationScope.BASE_EVIDENCE,
            tuple(path.relative_to(ctx.run.dir).parts),
            f"stale {key}\n".encode(),
        )
    result = SimpleNamespace(meta={"native_outputs": {"current_paths": []}})

    snapshot = crawl._xnl_snapshot(outs, result)

    assert snapshot == {
        "links": ("absent", b""),
        "params": ("absent", b""),
        "secrets": ("absent", b""),
        "wordlist": ("absent", b""),
    }


def test_xnl_materialize_seal_race_fails_closed_without_prior_mutation(
    tmp_path, monkeypatch,
):
    ctx = _running_context(tmp_path)
    outs = crawl._xnl_outputs(ctx, "js")
    links_components = tuple(outs["links"].relative_to(ctx.run.dir).parts)
    ctx.run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE, links_components, b"prior links\n",
    )
    snapshot = {
        "links": ("ok", b"replacement links\n"),
        "params": ("absent", b""),
        "secrets": ("absent", b""),
        "wordlist": ("absent", b""),
    }
    real_publish = crawl._xnl_publish_run_bytes
    fired = False

    def seal_then_publish(run, components, data):
        nonlocal fired
        if not fired:
            fired = True
            run.begin_finalization()
        return real_publish(run, components, data)

    monkeypatch.setattr(crawl, "_xnl_publish_run_bytes", seal_then_publish)
    with pytest.raises(OSError, match="could not be materialized"):
        crawl._xnl_materialize(ctx, "js", snapshot)

    assert fired and outs["links"].read_bytes() == b"prior links\n"
    assert ctx.run.state == "finalizing"
    assert ctx.run._live_artifact_claim_count() == 0


def test_xnl_present_materialization_cancellation_preserves_exact_exception(
    tmp_path, monkeypatch,
):
    ctx = _running_context(tmp_path)
    outs = crawl._xnl_outputs(ctx, "js")
    cancellation = KeyboardInterrupt("cancel XNL materialization")
    real_write = crawl._repository_write_all

    def cancel_after_write(descriptor, data):
        real_write(descriptor, data)
        raise cancellation

    monkeypatch.setattr(crawl, "_repository_write_all", cancel_after_write)
    snapshot = {
        "links": ("ok", b"current\n"),
        "params": ("absent", b""),
        "secrets": ("absent", b""),
        "wordlist": ("absent", b""),
    }

    with pytest.raises(KeyboardInterrupt) as raised:
        crawl._xnl_materialize(ctx, "js", snapshot)

    assert raised.value is cancellation
    assert not outs["links"].exists()
    assert ctx.run._live_artifact_claim_count() == 0
