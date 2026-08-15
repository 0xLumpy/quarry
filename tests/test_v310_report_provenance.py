from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import events, privfs, shodan_host, store
from quarry_recon.phases import params, probe
from quarry_recon.runner import RunResult, Status


pytestmark = pytest.mark.offline


def test_gowitness_joins_target_image_and_complete_provider_record(tmp_path):
    shot_dir = tmp_path / "shots"
    shot_dir.mkdir()
    image = shot_dir / "https-example.test.png"
    image.write_bytes(b"PNG")
    report = shot_dir / "gowitness.jsonl"
    report.write_text(
        '{"url":"https://example.test/","final_url":"https://example.test/login",'
        '"file_name":"https-example.test.png","title":"Target title",'
        '"headers":[{"key":"X-Evidence","value":"exact"}]}\n',
        encoding="utf-8",
    )
    report.chmod(0o600)

    assert probe._gowitness_records(shot_dir) == [{
        "url": "https://example.test/",
        "final_url": "https://example.test/login",
        "file": str(image),
        "provider_record": {
            "url": "https://example.test/",
            "final_url": "https://example.test/login",
            "file_name": "https-example.test.png",
            "title": "Target title",
            "headers": [{"key": "X-Evidence", "value": "exact"}],
        },
        "sources": ["gowitness"],
        "raw_refs": [str(report), str(image)],
    }]


def test_gowitness_never_turns_an_image_path_or_unsafe_name_into_a_target(tmp_path):
    shot_dir = tmp_path / "shots"
    shot_dir.mkdir()
    (shot_dir / "orphan.png").write_bytes(b"PNG")
    (shot_dir / "gowitness.jsonl").write_text(
        '{"url":"https://one.test/","file_name":"../escape.png"}\n'
        '{"url":"https://two.test/","file_name":"missing.png"}\n',
        encoding="utf-8",
    )
    (shot_dir / "gowitness.jsonl").chmod(0o600)

    with pytest.raises(ValueError, match="safe target/image identity"):
        probe._gowitness_records(shot_dir)

    (shot_dir / "gowitness.jsonl").unlink()
    with pytest.raises(FileNotFoundError):
        probe._gowitness_records(shot_dir)


def test_gowitness_refuses_unbounded_or_non_private_provider_streams(tmp_path, monkeypatch):
    shot_dir = tmp_path / "shots"
    shot_dir.mkdir()
    report = shot_dir / "gowitness.jsonl"
    report.write_text('{"url":"https://example.test/","file_name":"image.png"}\n')
    (shot_dir / "image.png").write_bytes(b"PNG")
    report.chmod(0o644)

    with pytest.raises(ValueError, match="owner-private"):
        probe._gowitness_records(shot_dir)

    report.chmod(0o600)
    monkeypatch.setattr(probe.run_manifest, "MAX_STRUCTURED_FILE_BYTES", 8)
    with pytest.raises(ValueError, match="bounded owner-private"):
        probe._gowitness_records(shot_dir)


@pytest.mark.parametrize("row", [
    b"not-json\n",
    b"42\n",
    b'{"matched-at":"https://waf.test/","matcher-name":"a","matcher-name":"b"}\n',
    b'{"matched-at":"https://waf.test/","score":NaN}\n',
    b'{"matched-at":"https://waf.test/","score":9223372036854775808}\n',
])
def test_waf_provider_rows_are_strict_and_never_silently_dropped(tmp_path, row):
    run = _running_run(tmp_path, f"waf-invalid-{abs(hash(row))}")
    path = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "probe", "nuclei", "waf.jsonl"),
        b'{"matched-at":"https://valid.test/","matcher-name":"fixture"}\n' + row,
    )
    with pytest.raises(ValueError, match="provider JSONL row 2"):
        probe._waf_records(SimpleNamespace(run=run), path)


@pytest.mark.parametrize("row", [
    b"not-json\n",
    b"42\n",
    b'{"url":"https://x.test/","file_name":"x.png","file_name":"y.png"}\n',
    b'{"url":"https://x.test/","file_name":"x.png","score":Infinity}\n',
])
def test_gowitness_provider_rows_are_strict_and_never_silently_dropped(tmp_path, row):
    run = _running_run(tmp_path, f"gowitness-invalid-{abs(hash(row))}")
    shot_dir = run.fresh_artifact_dir("raw", "probe", "gowitness")
    path = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        tuple((*shot_dir.relative_to(run.dir).parts, "gowitness.jsonl")),
        b'{"url":"https://valid.test/","file_name":"valid.png"}\n' + row,
    )
    with pytest.raises(ValueError, match="provider JSONL row 2"):
        probe._gowitness_records(SimpleNamespace(run=run), shot_dir)


def _probe_context(run, *, screenshots: bool):
    def write_list(name, values):
        return run._replace_artifact(
            store.MutationScope.BASE_EVIDENCE, ("raw", "inputs", name),
            ("\n".join(values) + "\n").encode(),
        )

    return SimpleNamespace(
        run=run,
        profile=SimpleNamespace(http_rl=None, screenshots=screenshots, portscan=False, cidr=[]),
        scope=SimpleNamespace(
            passive_only=False, filter_hosts=lambda hosts, active=True: list(hosts),
            in_scope=lambda _host: True, is_oos=lambda _host: False,
        ),
        http_timeout=5,
        write_list=write_list,
        echo=lambda _message: None,
    )


@pytest.mark.parametrize("owner", ["nuclei", "gowitness"])
def test_probe_provider_parse_failure_is_accounted_and_does_not_abort_the_phase(
        tmp_path, monkeypatch, owner,
):
    run = _running_run(tmp_path, f"probe-provider-{owner}")
    run.add("resolved", {"host": "target.test", "a": ["203.0.113.9"]})
    run.add("live", {"url": "https://target.test/", "host": "target.test"})
    ctx = _probe_context(run, screenshots=owner == "gowitness")
    reached_tail = []
    monkeypatch.setattr(probe, "fingerprint_hosts", lambda *_args: [])
    monkeypatch.setattr(probe, "_shodan_pivots", lambda *_args: None)
    monkeypatch.setattr(probe, "_vhost_enum", lambda *_args: None)
    monkeypatch.setattr(probe, "shodan_host_lane", lambda *_args: reached_tail.append(True))
    monkeypatch.setattr(probe, "native_output_current", lambda *_args: True)
    monkeypatch.setattr(probe, "have", lambda tool: tool == owner)

    def execute(tool, argv, **_kwargs):
        if tool == "nuclei":
            output = Path(argv[argv.index("-o") + 1])
            run._replace_artifact(
                store.MutationScope.BASE_EVIDENCE,
                tuple(output.relative_to(run.dir).parts),
                b'{"matched-at":"https://valid.test/","matcher-name":"fixture"}\nnot-json\n',
            )
        else:
            shot_dir = Path(argv[argv.index("--screenshot-path") + 1])
            privfs.private_dir(shot_dir)
            run._replace_artifact(
                store.MutationScope.BASE_EVIDENCE,
                tuple((shot_dir / "valid.png").relative_to(run.dir).parts), b"PNG",
            )
            output = shot_dir / "gowitness.jsonl"
            run._replace_artifact(
                store.MutationScope.BASE_EVIDENCE,
                tuple(output.relative_to(run.dir).parts),
                b'{"url":"https://valid.test/","file_name":"valid.png"}\nnot-json\n',
            )
        return RunResult(tool, list(argv), Status.SUCCESS, 0, 0.01, None, 0,
                         meta={"started": True})

    monkeypatch.setattr(probe, "exec_tool", execute)
    monkeypatch.setattr(
        probe, "run_contract",
        lambda _source_id, argv, **kwargs: execute("gowitness", argv, **kwargs),
    )
    probe.run(ctx)

    owned = next(record for record in run.tool_runs("probe") if record.tool == owner)
    assert owned.status == Status.PARTIAL.value
    assert reached_tail == [True]
    assert run.count("tech" if owner == "nuclei" else "screenshot") == 0


def test_shodan_cve_review_preserves_the_exact_ip_relationship(tmp_path):
    added = []
    ctx = SimpleNamespace(
        run=SimpleNamespace(add=lambda entity, record: added.append((entity, record)) or True),
        scope=SimpleNamespace(in_scope=lambda _host: False, is_oos=lambda _host: False),
    )
    rec = shodan_host.HostRecord(ip="192.0.2.8", vulns=["CVE-2026-1234"])
    wrote = []
    artifact = tmp_path / "shodan.json"

    probe._shodan_host_ingest(
        ctx, SimpleNamespace(hosts=()), rec, artifact, wrote.append,
    )

    review = next(record for entity, record in added if entity == "review")
    assert review["ip"] == "192.0.2.8"
    assert review["cve"] == "CVE-2026-1234"
    assert review["raw_ref"] == str(artifact)


def _running_run(tmp_path, run_id):
    run = store.Run.create(tmp_path, "example.test", run_id=run_id)
    run.write_state("running")
    return run


def test_main_nuclei_finding_preserves_complete_bounded_provider_evidence(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "nuclei-provider")
    ctx = SimpleNamespace(
        run=run,
        http_timeout=30,
        echo=lambda _message: None,
    )
    provider = {
        "template-id": "http-proof",
        "matched-at": "https://example.test/admin",
        "info": {"name": "Exact proof", "severity": "high"},
        "request": "GET /admin HTTP/1.1",
        "response": "HTTP/1.1 200 OK",
        "extracted-results": ["marker"],
    }

    monkeypatch.setattr(events, "ledger", lambda *_a, **_k: None)
    monkeypatch.setattr(params.settings, "concurrency", lambda _key, default=None: default)
    monkeypatch.setattr(params, "nuclei_timeout", lambda *_a: 30)

    def scan(_ctx, _live, findings, _log, _profile):
        run._replace_artifact(
            store.MutationScope.BASE_EVIDENCE,
            tuple(findings.relative_to(run.dir).parts),
            (params.json.dumps(provider) + "\n").encode(),
        )
        return RunResult("nuclei", ["nuclei"], Status.SUCCESS, 0, 0.01, findings, 1)

    monkeypatch.setattr(params, "_nuclei_scan", scan)
    params._main_nuclei_lane(ctx, ["https://example.test"], SimpleNamespace(http_rl=0))

    finding = run.read("finding")[0]
    assert finding["provider_record"] == provider
    assert finding["request"] == provider["request"]
    assert finding["response"] == provider["response"]
    assert finding["extracted_results"] == ["marker"]
    assert finding["raw_ref"].endswith("/raw/params/nuclei/findings.jsonl")


def test_managed_nuclei_provider_stream_refuses_nonprivate_or_torn_bytes(tmp_path):
    run = _running_run(tmp_path, "nuclei-provider-refusal")
    path = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "params", "nuclei", "findings.jsonl"),
        b'{"template-id":"ok"}\n',
    )
    ctx = SimpleNamespace(run=run)

    path.chmod(0o644)
    with pytest.raises(ValueError, match="owner-private"):
        params._provider_jsonl_records(ctx, path)

    path.chmod(0o600)
    path.write_bytes(b'{"template-id":"torn"}')
    with pytest.raises(ValueError, match="torn final row"):
        params._provider_jsonl_records(ctx, path)


@pytest.mark.parametrize("row", [
    b"not-json\n",
    b"42\n",
    b'{"template-id":"one","template-id":"two"}\n',
    b'{"template-id":"bad","score":NaN}\n',
    b'{"template-id":"bad","score":Infinity}\n',
    b'{"template-id":"bad","value":"\\ud800"}\n',
    b'{"template-id":"bad","value":9223372036854775808}\n',
])
def test_nuclei_provider_stream_refuses_every_unprojectable_complete_row(tmp_path, row):
    run = _running_run(tmp_path, f"nuclei-invalid-{abs(hash(row))}")
    path = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "params", "nuclei", "findings.jsonl"),
        b'{"template-id":"valid"}\n' + row,
    )
    with pytest.raises(ValueError, match="provider JSONL row 2"):
        params._provider_jsonl_records(SimpleNamespace(run=run), path)


def test_native_redirect_finding_has_durable_exact_request_response_proof(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "redirect-provider")
    ctx = SimpleNamespace(
        run=run,
        scope=SimpleNamespace(active_allowed=lambda _host: True),
    )
    for name in ("tool_start", "tool_progress", "tool_finish"):
        monkeypatch.setattr(events, name, lambda *_a, **_k: None)
    monkeypatch.setattr(
        params.fetch,
        "redirect_location",
        lambda *_a, **_k: ("https://quarry-redirect-canary.example/rc", 302),
    )

    result = params._redirect_confirm(
        ctx, ["https://example.test/next?url=original"], SimpleNamespace(http_rl=0),
    )

    assert result.status is Status.SUCCESS and result.stdout_lines == 1
    finding = run.read("finding")[0]
    assert finding["request"] == {
        "method": "GET",
        "url": "https://example.test/next?url=https%3A%2F%2Fquarry-redirect-canary.example%2Frc",
        "follow_redirects": False,
    }
    assert finding["response"] == {
        "status": 302,
        "location": "https://quarry-redirect-canary.example/rc",
    }
    raw = run.dir / "raw" / "params" / "redirect-confirm" / "probes.jsonl"
    assert finding["raw_ref"] == str(raw)
    assert raw.is_file() and raw.stat().st_mode & 0o777 == 0o600
    assert params.json.loads(raw.read_text()) == finding["provider_record"]


def test_native_redirect_identity_cannot_collapse_long_distinct_candidates(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "redirect-distinct")
    ctx = SimpleNamespace(run=run, scope=SimpleNamespace(active_allowed=lambda _host: True))
    for name in ("tool_start", "tool_progress", "tool_finish"):
        monkeypatch.setattr(events, name, lambda *_a, **_k: None)
    monkeypatch.setattr(
        params.fetch, "redirect_location",
        lambda *_a, **_k: ("https://quarry-redirect-canary.example/rc", 302),
    )
    prefix = "https://example.test/" + "a" * 100
    candidates = [f"{prefix}?url=one", f"{prefix}?url=two"]

    result = params._redirect_confirm(ctx, candidates, SimpleNamespace(http_rl=0))

    findings = run.read("finding")
    assert result.stdout_lines == 2
    assert len(findings) == 2
    assert len({row["id"] for row in findings}) == 2
