"""V310-09: one immutable run policy for every Nuclei owner and an independent OOB switch."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import (cli, config, exit_contract, nuclei_policy, oob, registry, run_manifest,
                          runtime_identity, settings, store, views)
from quarry_recon.phases import PhaseContext, params
from quarry_recon.state import ContractError


pytestmark = pytest.mark.offline


def _engine(path: str = "/opt/quarry/nuclei") -> dict:
    return {
        "attestation": "host-digest",
        "executable": {"bytes": 7, "path": path, "role": "executable",
                       "sha256": "1" * 64, "mode": 0o755},
        "identity": "distro@sha256:" + "1" * 64,
        "runtime": "host",
        "runtime_root": str(Path(path).parent),
        "closure": None,
    }


def _profile(*, oob=True, private=False, rate=5, blind=False):
    return SimpleNamespace(oob_enabled=oob, block_private_targets=private, http_rl=rate,
                           blind_xss=blind)


def _corpus(root: Path) -> tuple[Path, Path]:
    templates, cfg = root / "nuclei-templates", root / "nuclei-config"
    (templates / "helpers").mkdir(parents=True)
    cfg.mkdir()
    (templates / "helpers" / "payload.txt").write_text("one\ntwo\n")
    (templates / "broad.yaml").write_text(
        "id: broad\ninfo:\n  severity: high\n  tags: [cve]\n"
        "http:\n- method: GET\n  payloads:\n    value: helpers/payload.txt\n"
        "# digest: signed-marker\n"
    )
    (templates / "intrusive.yaml").write_text(
        "id: intrusive\ninfo:\n  severity: critical\n  tags: [intrusive]\n"
        "http:\n- method: GET\n"
    )
    (templates / "takeover.yaml").write_text(
        "id: takeover\ninfo:\n  severity: low\n  tags: [takeover]\n"
        "dns:\n- name: '{{FQDN}}'\n  type: A\n"
    )
    (templates / "waf.yaml").write_text(
        "id: waf\ninfo:\n  severity: info\n  tags: waf\nhttp:\n- method: GET\n"
    )
    (cfg / ".templates-config.json").write_text('{"nuclei-templates-version":"v10"}\n')
    (cfg / ".nuclei-ignore").write_text("tags: []\nfiles: []\n")
    (cfg / "config.yaml").write_text("# intentionally empty accepted-policy config\n")
    return templates, cfg


@pytest.fixture
def fixed_settings(monkeypatch):
    monkeypatch.setattr(settings, "workers", lambda name, default: 17 if name == "nuclei" else default)
    monkeypatch.setattr(settings, "concurrency", lambda name, default=None: {
        "NUCLEI_BULK_SIZE": 11, "NUCLEI_CHUNK_HOSTS": 2,
    }.get(name, default))
    monkeypatch.setattr(settings, "performance", lambda: {})


def test_offline_inventory_selects_each_owner_and_binds_helpers(tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    document = nuclei_policy.build_document(
        run_id="run-a", profile=_profile(), template_root=templates, config_root=cfg,
        engine_identity=_engine(), engine_pin="v3.11.0",
    )

    owners = {row["owner"]: row for row in document["owners"]}
    assert [row["id"] for row in owners["params.nuclei_scan"]["selected_templates"]] == ["broad"]
    assert [row["id"] for row in owners["params.nuclei_takeover"]["selected_templates"]] == ["takeover"]
    assert [row["id"] for row in owners["probe.nuclei_waf"]["selected_templates"]] == ["waf"]
    assert (owners["probe.nuclei_waf"]["selection_digest"]
            == owners["enrich.nuclei_waf"]["selection_digest"])
    assert [row["path"] for row in document["helpers"]] == ["helpers/payload.txt"]
    assert next(row for row in owners["params.nuclei_scan"]["selected_templates"]
                if row["id"] == "broad")["signature_state"] == "digest-marker-present-unverified"
    assert next(row for row in owners["params.nuclei_scan"]["selected_templates"]
                if row["id"] == "broad")["request_protocols"] == ["http"]
    assert owners["params.nuclei_takeover"]["selected_templates"][0]["primary_protocol"] == "dns"
    assert [row["protocol"] for row in owners["params.nuclei_scan"]["protocol_partitions"]] \
        == ["http", "dns", "tcp"]
    assert document["engine"]["declared_pin"] == "v3.11.0"
    nuclei_policy.validate_document(json.loads(json.dumps(document)))


def test_target_hosts_are_the_exact_canonical_chunk_authorities():
    assert nuclei_policy.target_hosts([
        "https://api.acme.test:8443/a", "api.acme.test", "http://[2001:db8::1]/",
        "https://api.acme.test/b",
    ]) == ("2001:db8::1", "api.acme.test")
    assert nuclei_policy.target_hosts([
        "2001:0DB8:0:0::1", "::ffff:192.0.2.1", "192.0.2.2",
    ]) == ("192.0.2.1", "192.0.2.2", "2001:db8::1")
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="canonical authority"):
        nuclei_policy.target_hosts(["fe80::1%eth0"])
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="canonical authority"):
        nuclei_policy.target_hosts(["https://user@acme.test/"])
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="no canonical authority"):
        nuclei_policy.target_hosts([])


def test_oob_false_adds_ni_to_every_owner_without_changing_private_default(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(
        nuclei_policy.secrets, "oob",
        lambda: pytest.fail("OOB-disabled policy read a credential source"),
    )
    templates, cfg = _corpus(tmp_path)
    document = nuclei_policy.build_document(
        run_id="run-off", profile=_profile(oob=False), template_root=templates, config_root=cfg,
        engine_identity=_engine(),
    )
    assert {key: document["modes"][key] for key in (
        "oob_enabled", "oob_backend", "oob_server", "oob_auth", "block_private_targets",
    )} == {"oob_enabled": False, "oob_backend": "off", "oob_server": None,
           "oob_auth": "none", "block_private_targets": False}
    assert document["modes"]["oob_auth_identity"] is None
    assert document["modes"]["oob_config_identity"].startswith("sha256:")
    assert all("-ni" in row["flags"] for row in document["owners"])
    assert "must-not-enter-policy" not in json.dumps(document)

    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {
        "callback_server": "https://oob.example", "auth_token": "must-not-enter-policy",
    })
    enabled = nuclei_policy.build_document(
        run_id="run-on", profile=_profile(oob=True), template_root=templates, config_root=cfg,
        engine_identity=_engine(),
    )
    assert enabled["modes"]["oob_backend"] == "self-hosted"
    assert enabled["modes"]["oob_server"] == "https://oob.example"
    assert enabled["modes"]["oob_auth"] == "private-config"
    assert "must-not-enter-policy" not in json.dumps(enabled)
    assert all("-ni" not in row["flags"] for row in enabled["owners"])
    assert all(row["flags"][-2:] == ["-iserver", "https://oob.example"]
               and row["private_config"] == "interactsh-token" for row in enabled["owners"])


def test_oob_server_cannot_smuggle_credentials_into_policy_or_argv(
        tmp_path, fixed_settings, monkeypatch):
    templates, cfg = _corpus(tmp_path)
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {
        "callback_server": "https://user:secret@oob.example/path?token=canary",
        "auth_token": "separate-secret",
    })
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="secret URL parts"):
        nuclei_policy.build_document(
            run_id="bad-oob", profile=_profile(), template_root=templates, config_root=cfg,
            engine_identity=_engine(),
        )


def test_policy_digest_rejects_nested_owner_or_inventory_mutation(tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    document = nuclei_policy.build_document(
        run_id="run-a", profile=_profile(), template_root=templates, config_root=cfg,
        engine_identity=_engine(),
    )
    for mutate in (
        lambda d: d["owners"][3]["flags"].append("-headless"),
        lambda d: d["corpus"]["inventory"][0].update(bytes=999),
        lambda d: d["modes"].update(oob_backend="off"),
    ):
        changed = json.loads(json.dumps(document))
        mutate(changed)
        with pytest.raises(nuclei_policy.NucleiPolicyError):
            nuclei_policy.validate_document(changed)


def test_validator_rejects_redigested_coverage_or_flag_policy_forgery(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    document = nuclei_policy.build_document(
        run_id="forgery", profile=_profile(), template_root=templates, config_root=cfg,
        engine_identity=_engine(),
    )
    for forge in ("flags", "selection"):
        changed = json.loads(json.dumps(document))
        owner = changed["owners"][-1]
        if forge == "flags":
            owner["flags"][owner["flags"].index("critical,high,medium")] = "low"
            owner["flags_digest"] = nuclei_policy._sha256(nuclei_policy._canonical({
                "flags": owner["flags"], "private_config": owner["private_config"],
            }))
        else:
            owner["selected_templates"][0]["tags"].append("intrusive")
            owner["selected_templates"][0]["tags"].sort()
            owner["selection_digest"] = nuclei_policy._sha256(
                nuclei_policy._canonical(owner["selected_templates"]),
            )
            owner["protocol_partitions"] = nuclei_policy._protocol_partitions(
                owner["selected_templates"],
            )
        changed["policy_digest"] = None
        changed["policy_digest"] = nuclei_policy._sha256(nuclei_policy._canonical(changed))
        with pytest.raises(nuclei_policy.NucleiPolicyError, match="accepted"):
            nuclei_policy.validate_document(changed)


def test_frozen_self_hosted_oob_transport_is_exact_for_all_four_owners(
        tmp_path, fixed_settings, monkeypatch):
    token = "V310-NUCLEI-POLICY-CANARY"
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {
        "callback_server": "https://oob.example", "auth_token": token,
    })
    templates, cfg = _corpus(tmp_path)
    document = nuclei_policy.build_document(
        run_id="oob-frozen", profile=_profile(), template_root=templates, config_root=cfg,
        engine_identity=_engine(),
    )
    authority = nuclei_policy.Authority(
        document=document, path=tmp_path / "unused-policy", artifact_bytes=b"",
        template_path=templates, config_path=cfg, template_check={}, config_check={},
        engine_identity=_engine(),
        oob_config={"callback_server": "https://oob.example", "auth_token": token},
    )
    for owner_name in nuclei_policy.OWNERS:
        row = authority.owner(owner_name)
        protocol_lane = authority.protocol_lanes(owner_name)[0]
        with authority.oob_flags() as oob_flags:
            assert oob_flags[:2] == ("-iserver", "https://oob.example")
            assert token not in oob_flags and "-itoken" not in oob_flags
            config_path = Path(oob_flags[oob_flags.index("-config") + 1])
            command = ["nuclei", "-l", "/input", "-jsonl", "-o", "/output",
                       "-pt", protocol_lane,
                       *row["flags"], "-config", str(config_path)]
            nuclei_policy._assert_command(
                row, command, oob_enabled=True, expected_private_config=config_path,
                allowed_protocol_lanes=authority.protocol_lanes(owner_name),
            )
        assert not config_path.parent.exists()


def test_command_policy_rejects_duplicate_or_unrecorded_coverage_flags(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    document = nuclei_policy.build_document(
        run_id="argv", profile=_profile(), template_root=templates, config_root=cfg,
        engine_identity=_engine(),
    )
    row = next(owner for owner in document["owners"] if owner["owner"] == "params.nuclei_scan")
    base = ["nuclei", "-l", "/input", "-jsonl", "-o", "/output",
            "-pt", "http,dns", *row["flags"]]
    for addition in (("-s", "low"), ("-headless",), ("-itoken", "secret")):
        with pytest.raises(nuclei_policy.NucleiPolicyError):
            nuclei_policy._assert_command(
                row, [*base, *addition], oob_enabled=True, expected_private_config=None,
                allowed_protocol_lanes=("http,dns", "tcp"),
            )


def test_schema_accepts_the_canonical_document_when_jsonschema_is_available(
        tmp_path, fixed_settings, monkeypatch):
    jsonschema = pytest.importorskip("jsonschema")
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    document = nuclei_policy.build_document(
        run_id="run-a", profile=_profile(), template_root=templates, config_root=cfg,
        engine_identity=_engine(),
    )
    schema = json.loads((Path(__file__).parents[1] / "release" / "evidence" / "schemas"
                         / "nuclei-policy-v1.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(document, schema)


def test_run_authority_publishes_once_and_all_four_launches_share_exact_snapshots(
        tmp_path, fixed_settings, monkeypatch):
    home = tmp_path / "home"
    templates, cfg = _corpus(home)
    executable = tmp_path / "bin" / "nuclei"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    tool = registry.Tool(bin="nuclei", phase="params", role="fixture", policy="distro",
                         env_allow=["NUCLEI_CONFIG_DIR", "NUCLEI_TEMPLATES_DIR"])
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("NUCLEI_CONFIG", str(cfg))
    monkeypatch.setenv("PATH", str(executable.parent))
    monkeypatch.setattr(registry, "tool_for_bin", lambda name: tool if name == "nuclei" else None)
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})

    run = store.Run.create(tmp_path / "project", "acme.example", run_id="v310-nuclei")
    run.write_state("running")
    ctx = PhaseContext(run=run, profile=_profile(), scope=SimpleNamespace(), workdir=run.dir / "work")
    dynamic_paths, config_paths = [], []
    with nuclei_policy.run_authority(ctx) as authority:
        ctx.nuclei_policy = authority
        assert authority.path.is_file()
        artifact = json.loads(authority.path.read_text())
        assert artifact["policy_digest"] == authority.digest
        assert artifact["corpus"]["source_state"] == "detached-tree"
        assert artifact["config"]["source_state"] == "detached-tree"
        summary = authority.manifest_summary()
        assert summary["corpus_trust"] == "unverified-inventory-only-not-an-authorship-claim"
        assert all(row["oob_backend"] == "public-interactsh" for row in summary["owners"])
        for owner in nuclei_policy.OWNERS:
            row = authority.owner(owner)
            command = ["nuclei", "-l", "/tmp/in", "-jsonl", "-o", "/tmp/out", *row["flags"]]
            prepared = runtime_identity.prepare_launch("nuclei", command)
            try:
                dynamic = next(item for item in prepared.record["dynamic_closure"]
                               if item["role"] == "nuclei-templates")
                private = next(item for item in prepared.private_checks if item["role"] == "nuclei-config")
                dynamic_paths.append(dynamic["path"])
                config_paths.append(private["anchor"])
                assert "-t" in prepared.argv
                assert "NUCLEI_CONFIG" not in prepared.environment
                assert prepared.environment["NUCLEI_CONFIG_DIR"] == private["anchor"]
                assert prepared.environment["NUCLEI_TEMPLATES_DIR"] == dynamic["path"]
                assert prepared.environment["XDG_CONFIG_HOME"] == str(Path(private["anchor"]).parent)
                assert prepared.environment["HOME"] != str(home)
            finally:
                prepared.close()
        assert len(set(dynamic_paths)) == len(set(config_paths)) == 1
        assert dynamic_paths[0] == str(authority.template_path)
        assert config_paths[0] == str(authority.config_path)


def test_mutated_engine_is_refused_before_a_launch(tmp_path, fixed_settings, monkeypatch):
    home = tmp_path / "home"
    _templates, cfg = _corpus(home)
    executable = tmp_path / "bin" / "nuclei"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    tool = registry.Tool(bin="nuclei", phase="params", role="fixture", policy="distro",
                         env_allow=["NUCLEI_CONFIG_DIR", "NUCLEI_TEMPLATES_DIR"])
    monkeypatch.setenv("HOME", str(home)); monkeypatch.setenv("NUCLEI_CONFIG", str(cfg))
    monkeypatch.setenv("PATH", str(executable.parent))
    monkeypatch.setattr(registry, "tool_for_bin", lambda name: tool if name == "nuclei" else None)
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    run = store.Run.create(tmp_path / "project", "acme.example", run_id="v310-mutation")
    run.write_state("running")
    ctx = PhaseContext(run=run, profile=_profile(), scope=SimpleNamespace(), workdir=run.dir / "work")
    with nuclei_policy.run_authority(ctx) as authority:
        executable.write_text("#!/bin/sh\necho changed\n")
        executable.chmod(0o755)
        with pytest.raises(nuclei_policy.NucleiPolicyError, match="engine identity changed"):
            authority.assert_ready()
        with pytest.raises(runtime_identity.RuntimeIdentityError, match="active policy"):
            runtime_identity.prepare_launch("nuclei", ["nuclei", "-version"])


def test_missing_or_changed_policy_artifact_is_fail_closed(tmp_path, fixed_settings, monkeypatch):
    home = tmp_path / "home"
    _templates, cfg = _corpus(home)
    monkeypatch.setenv("HOME", str(home)); monkeypatch.setenv("NUCLEI_CONFIG", str(cfg))
    monkeypatch.setattr(nuclei_policy, "_engine_identity", lambda: (_engine(), "v3.11.0"))
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    run = store.Run.create(tmp_path / "project", "acme.example", run_id="v310-policy-file")
    run.write_state("running")
    ctx = PhaseContext(run=run, profile=_profile(), scope=SimpleNamespace(), workdir=run.dir / "work")
    with nuclei_policy.run_authority(ctx) as authority:
        authority.path.write_text("{}")
        with pytest.raises(nuclei_policy.NucleiPolicyError, match="changed"):
            authority.assert_ready()


def test_policy_digest_is_part_of_resume_identity(tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    first = nuclei_policy.build_document(
        run_id="same-run", profile=_profile(oob=True), template_root=templates, config_root=cfg,
        engine_identity=_engine(),
    )
    second = nuclei_policy.build_document(
        run_id="same-run", profile=_profile(oob=False), template_root=templates, config_root=cfg,
        engine_identity=_engine(),
    )
    from quarry_recon import events
    a = events.work_unit("params.nuclei_scan", inputs={"hosts": ["a"]},
                         config={"chunk": 2, "policy": first["policy_digest"]})
    b = events.work_unit("params.nuclei_scan", inputs={"hosts": ["a"]},
                         config={"chunk": 2, "policy": second["policy_digest"]})
    assert a != b


def test_ignore_file_is_applied_to_exact_owner_selection(tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    (templates / "ignored-tag.yaml").write_text(
        "id: ignored-tag\ninfo:\n  severity: high\n  tags: [local]\nhttp:\n- method: GET\n"
    )
    (templates / "ignored-file.yaml").write_text(
        "id: ignored-file\ninfo:\n  severity: high\n  tags: [cve]\nhttp:\n- method: GET\n"
    )
    (cfg / ".nuclei-ignore").write_text(
        "tags: [local]\nfiles: [ignored-file.yaml]\n"
    )
    document = nuclei_policy.build_document(
        run_id="ignore", profile=_profile(), template_root=templates, config_root=cfg,
        engine_identity=_engine(),
    )
    main = next(row for row in document["owners"] if row["owner"] == "params.nuclei_scan")
    assert [row["id"] for row in main["selected_templates"]] == ["broad"]
    assert document["ignore"]["tags"] == ["local"]
    assert document["ignore"]["files"] == ["ignored-file.yaml"]


def test_semantic_risk_is_versioned_reconciled_telemetry_not_a_filter(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    (templates / "state.yaml").write_text(
        "id: state-change\ninfo:\n  severity: high\n  tags: [cve]\n"
        "http:\n- method: POST\n  body: enabled=true\n"
    )
    document = nuclei_policy.build_document(
        run_id="semantic", profile=_profile(), template_root=templates, config_root=cfg,
        engine_identity=_engine(),
    )
    main = next(row for row in document["owners"] if row["owner"] == "params.nuclei_scan")
    selected = {row["id"]: row for row in main["selected_templates"]}
    assert selected["state-change"]["semantic_class"] == "potentially_state_changing"
    assert {"broad", "state-change"} == set(selected)
    assert main["semantic_inventory"]["counts"] == {
        "not_detected": 1, "potentially_state_changing": 1, "unknown": 0,
    }
    assert document["semantic_classifier"]["effect"] == "telemetry-only-never-filters-selection"
    nuclei_policy.validate_document(document)


def test_mixed_dns_http_template_has_engine_primary_dns_and_one_partition(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    (templates / "mixed.yaml").write_text(
        "id: mixed-dns-http\ninfo: {severity: high, tags: [cve]}\n"
        "dns:\n- name: '{{FQDN}}'\n  type: A\n"
        "http:\n- method: GET\n"
    )
    (templates / "tcp.yaml").write_text(
        "id: tcp-only\ninfo: {severity: high, tags: [cve]}\n"
        "tcp:\n- host: ['{{Hostname}}']\n"
    )
    document = nuclei_policy.build_document(
        run_id="mixed-protocol", profile=_profile(oob=False), template_root=templates,
        config_root=cfg, engine_identity=_engine(), engine_pin="v3.11.0",
    )
    owner = next(row for row in document["owners"] if row["owner"] == "params.nuclei_scan")
    selected = next(row for row in owner["selected_templates"] if row["id"] == "mixed-dns-http")
    assert selected["primary_protocol"] == "dns"
    assert selected["request_protocols"] == ["dns", "http"]
    partitions = {row["protocol"]: row for row in owner["protocol_partitions"]}
    assert "mixed.yaml" in partitions["dns"]["selected_paths"]
    assert "mixed.yaml" not in partitions["http"]["selected_paths"]
    assert partitions["tcp"]["selected_paths"] == ["tcp.yaml"]
    assert sum(row["selected_count"] for row in partitions.values()) == owner["selected_count"]
    authority = nuclei_policy.Authority(
        document=document, path=tmp_path / "unused-policy", artifact_bytes=b"",
        template_path=templates, config_path=cfg, template_check={}, config_check={},
        engine_identity=_engine(),
    )
    assert authority.protocol_lanes("params.nuclei_scan") == ("http,dns", "tcp")
    webdns = authority.lane("params.nuclei_scan", "http,dns")
    tcp = authority.lane("params.nuclei_scan", "tcp")
    assert webdns["selected_count"] + tcp["selected_count"] == owner["selected_count"]
    assert webdns["selection_digest"] != tcp["selection_digest"]


def test_command_policy_requires_one_accepted_protocol_lane(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    document = nuclei_policy.build_document(
        run_id="lane-command", profile=_profile(), template_root=templates,
        config_root=cfg, engine_identity=_engine(),
    )
    authority = nuclei_policy.Authority(
        document=document, path=tmp_path / "unused-policy", artifact_bytes=b"",
        template_path=templates, config_path=cfg, template_check={}, config_check={},
        engine_identity=_engine(),
    )
    row = authority.owner("params.nuclei_scan")
    base = ["nuclei", "-l", "/input", "-jsonl", "-o", "/output", *row["flags"]]
    for lane_args in ((), ("-pt", "tcp"),
                      ("-pt", "http,dns", "-pt", "http,dns")):
        with pytest.raises(nuclei_policy.NucleiPolicyError, match="protocol lane"):
            nuclei_policy._assert_command(
                row, [*base, *lane_args], oob_enabled=True,
                expected_private_config=None,
                allowed_protocol_lanes=authority.protocol_lanes("params.nuclei_scan"),
            )


@pytest.mark.parametrize(("request_body", "message"), [
    ("custom-protocol: true\n", "no canonical request protocol"),
    ("http: {method: GET}\n", "malformed request sections"),
    ("http:\n- method: GET\nrequests:\n- method: GET\n", "mutually exclusive request aliases"),
    ("tcp:\n- host: ['{{Hostname}}']\nnetwork:\n- host: ['{{Hostname}}']\n",
     "mutually exclusive request aliases"),
    ("http:\n- method: GET\nssl:\n- address: '{{Host}}:443'\n", "unsupported request protocols"),
])
def test_selected_protocol_metadata_fails_closed_on_unknown_malformed_or_unsupported(
        tmp_path, fixed_settings, monkeypatch, request_body, message):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    (templates / "invalid-protocol.yaml").write_text(
        "id: invalid-protocol\ninfo: {severity: high, tags: [cve]}\n" + request_body
    )
    with pytest.raises(nuclei_policy.NucleiPolicyError, match=message):
        nuclei_policy.build_document(
            run_id="invalid-protocol", profile=_profile(oob=False), template_root=templates,
            config_root=cfg, engine_identity=_engine(), engine_pin="v3.11.0",
        )


def test_validator_rejects_redigested_non_disjoint_protocol_partition(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    document = nuclei_policy.build_document(
        run_id="partition-forgery", profile=_profile(oob=False), template_root=templates,
        config_root=cfg, engine_identity=_engine(), engine_pin="v3.11.0",
    )
    changed = json.loads(json.dumps(document))
    owner = next(row for row in changed["owners"] if row["owner"] == "params.nuclei_scan")
    http, dns, _tcp = owner["protocol_partitions"]
    dns["selected_paths"].append(http["selected_paths"][0])
    dns["selected_count"] += 1
    changed["policy_digest"] = None
    changed["policy_digest"] = nuclei_policy._sha256(nuclei_policy._canonical(changed))
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="disjoint complete"):
        nuclei_policy.validate_document(changed)


def test_active_nuclei_flags_config_is_refused(tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    (cfg / "config.yaml").write_text("headless: true\n")
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="active settings"):
        nuclei_policy.build_document(
            run_id="active-config", profile=_profile(), template_root=templates, config_root=cfg,
            engine_identity=_engine(),
        )


def test_recursive_and_excessive_alias_yaml_are_refused(tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    (templates / "cycle.yaml").write_text(
        "id: cycle\ninfo:\n  severity: high\n  tags: [intrusive]\nvariables: &loop [*loop]\n"
    )
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="recursive alias"):
        nuclei_policy.build_document(
            run_id="cycle", profile=_profile(), template_root=templates, config_root=cfg,
            engine_identity=_engine(),
        )
    (templates / "cycle.yaml").write_text(
        "id: aliases\ninfo: &i\n  severity: high\n  tags: [intrusive]\ncopy1: *i\ncopy2: *i\n"
    )
    monkeypatch.setattr(nuclei_policy, "_yaml_alias_bound", 1)
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="alias bound"):
        nuclei_policy.build_document(
            run_id="aliases", profile=_profile(), template_root=templates, config_root=cfg,
            engine_identity=_engine(),
        )


def test_malformed_excluded_template_is_refused_before_selection(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    (templates / "malformed.yaml").write_text(
        "id: malformed\ninfo:\n  severity: high\n  tags: [intrusive]\nhttp: [unterminated\n"
    )
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="cannot be inventoried offline"):
        nuclei_policy.build_document(
            run_id="malformed", profile=_profile(), template_root=templates, config_root=cfg,
            engine_identity=_engine(),
        )


def test_yaml_depth_bytes_and_tree_file_bounds_are_refused(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    nested = ("id: deep\ninfo:\n  severity: high\n  tags: [intrusive]\nroot:\n"
              + "\n".join("  " * depth + "x:" for depth in range(1, 21)) + "\n")
    (templates / "deep.yaml").write_text(nested)
    monkeypatch.setattr(nuclei_policy, "_yaml_depth_bound", 10)
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="depth bound"):
        nuclei_policy.build_document(
            run_id="depth", profile=_profile(), template_root=templates, config_root=cfg,
            engine_identity=_engine(),
        )
    monkeypatch.setattr(nuclei_policy, "_yaml_depth_bound", 96)
    monkeypatch.setattr(nuclei_policy, "_yaml_byte_bound", 16)
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="byte bound"):
        nuclei_policy.build_document(
            run_id="bytes", profile=_profile(), template_root=templates, config_root=cfg,
            engine_identity=_engine(),
        )
    monkeypatch.setattr(nuclei_policy, "_yaml_byte_bound", 16 * 1024 * 1024)
    monkeypatch.setattr(nuclei_policy, "_tree_file_bound", 2)
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="object bound|file/byte bound"):
        nuclei_policy.build_document(
            run_id="files", profile=_profile(), template_root=templates, config_root=cfg,
            engine_identity=_engine(),
        )


def test_mutation_between_inventory_and_parse_is_refused(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    original = nuclei_policy._inventory

    def inventory_then_mutate(root):
        rows = original(root)
        if Path(root) == templates:
            (templates / "broad.yaml").write_text(
                "id: replacement\ninfo:\n  severity: high\n  tags: [cve]\n"
                "http:\n- method: GET\n"
            )
        return rows

    monkeypatch.setattr(nuclei_policy, "_inventory", inventory_then_mutate)
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="changed after inventory"):
        nuclei_policy.build_document(
            run_id="mutation", profile=_profile(), template_root=templates, config_root=cfg,
            engine_identity=_engine(),
        )


def test_registry_declares_only_real_upstream_nuclei_environment_names():
    tool = registry.tool_for_bin("nuclei")
    assert tool is not None
    assert set(tool.env_allow or ()) == {"NUCLEI_CONFIG_DIR", "NUCLEI_TEMPLATES_DIR"}
    assert "NUCLEI_CONFIG" not in (tool.env_allow or ())


def test_independent_oob_disable_keeps_local_import_and_blocks_every_network_owner(
        tmp_path, monkeypatch):
    profile = SimpleNamespace(oob_enabled=False, blind_xss=True)
    assert params._blind_oob_plan(profile)["channel"] == "off"
    monkeypatch.setattr(params, "have", lambda _name: pytest.fail("disabled Quarry probe queried a binary"))
    recorded = []
    ctx = SimpleNamespace(run=SimpleNamespace(record=lambda *args, **kwargs: recorded.append((args, kwargs))))
    scope = SimpleNamespace(passive_only=False)
    assert params._oob_probe(ctx, scope, profile) is None
    assert "OOB_ENABLED" in recorded[0][0][1].note

    monkeypatch.setattr(cli.TargetProfile, "load", lambda _path: profile)
    monkeypatch.setattr(cli, "_resolve_profile", lambda value: value)
    monkeypatch.setattr(cli, "_existing_run", lambda *_args: pytest.fail("poll touched a run"))
    with pytest.raises(exit_contract.Refused, match="local `quarry oob import` remains available"):
        cli._oob_poll(str(tmp_path / "target.yaml"), None, 0, {})
    # The local import path has no OOB_ENABLED gate; it remains a pure ingest of supplied bytes.
    assert "oob_enabled" not in cli._oob_import.__code__.co_names


def test_oob_poll_cannot_enable_network_for_a_resumed_disabled_run(tmp_path, monkeypatch):
    profile = SimpleNamespace(oob_enabled=True, target="x", path=tmp_path / "target.yaml")
    run = SimpleNamespace(
        run_id="recorded-off", manifest_path=tmp_path / "manifest.json",
        manifest_committed=lambda: True,
    )
    monkeypatch.setattr(cli.TargetProfile, "load", lambda _path: profile)
    monkeypatch.setattr(cli, "_resolve_profile", lambda value: value)
    monkeypatch.setattr(cli, "_existing_run", lambda *_args: run)
    monkeypatch.setattr(
        run_manifest, "read",
        lambda _path: SimpleNamespace(document={"profile": {"oob_enabled": False}}),
    )
    monkeypatch.setattr(
        cli.secrets, "oob", lambda: pytest.fail("refused resume read an OOB credential source"),
    )
    with pytest.raises(exit_contract.Refused, match="cannot be enabled after the fact"):
        cli._oob_poll(str(tmp_path / "target.yaml"), run.run_id, 0, {})


def test_target_modes_are_strict_and_independent(tmp_path):
    base = {
        "TARGET": "x", "APEX_DOMAINS": ["example.com"], "OOS": [], "CIDR": [], "ASN": [],
        "RATELIMIT": {}, "PORTS": {"HTTP": []}, "NOTES": [],
    }
    path = tmp_path / "target.yaml"
    import yaml
    path.write_text(yaml.safe_dump({**base, "MODES": {}}))
    profile = config.TargetProfile.load(path)
    assert profile.oob_enabled is True and profile.block_private_targets is False
    path.write_text(yaml.safe_dump({**base, "MODES": {
        "OOB_ENABLED": "false", "BLOCK_PRIVATE_TARGETS": "true",
    }}))
    profile = config.TargetProfile.load(path)
    assert profile.oob_enabled is False and profile.block_private_targets is True
    path.write_text(yaml.safe_dump({**base, "MODES": {"OOB_ENABLED": "maybe"}}))
    with pytest.raises(config.ProfileError, match="invalid boolean"):
        config.TargetProfile.load(path)


def test_engine_format_and_yaml_metadata_parity(tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    (templates / "active.json").write_text(json.dumps({
        "id": "json-active", "info": {"severity": "high", "tags": ["cve"]},
        "http": [{"method": "GET"}],
    }))
    (templates / "flow.yaml").write_text(
        '{"id": "flow-active", "info": {"severity": "high", "tags": ["cve"]}, '
        '"http": [{"method": "GET"}]}\n'
    )
    (templates / "unsupported.yml").write_text(
        "id: yml-active\ninfo: {severity: high, tags: [cve]}\nhttp:\n- method: GET\n"
    )
    archive = templates / "cves.json-archive"
    archive.mkdir()
    (archive / "kept.yaml").write_text(
        "id: config-name-in-directory\ninfo: {severity: high, tags: [cve]}\n"
        "http:\n- method: GET\n"
    )
    (templates / "prefix-cves.json-suffix.json").write_text(json.dumps({
        "id": "known-config-basename", "info": {"severity": "high", "tags": ["cve"]},
        "http": [{"method": "GET"}],
    }))
    document = nuclei_policy.build_document(
        run_id="formats", profile=_profile(oob=False), template_root=templates, config_root=cfg,
        engine_identity=_engine(), engine_pin="v3.11.0",
    )
    selected = {row["id"] for row in document["owners"][-1]["selected_templates"]}
    assert {"json-active", "flow-active", "broad", "config-name-in-directory"} <= selected
    assert not selected & {"yml-active", "known-config-basename"}


def test_ignore_directory_and_engine_misc_directories_are_not_selected(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    (cfg / ".nuclei-ignore").write_text("tags: []\nfiles: [http]\n")
    for directory in (templates / "http", templates / "helpers", templates / ".github"):
        directory.mkdir(exist_ok=True)
    body = "info:\n  severity: high\n  tags: [cve]\nhttp: []\n"
    (templates / "http" / "ignored.yaml").write_text("id: ignored-directory\n" + body)
    (templates / "helpers" / "not-template.yaml").write_text("id: helper-directory\n" + body)
    (templates / ".github" / "not-template.yaml").write_text("id: github-directory\n" + body)
    document = nuclei_policy.build_document(
        run_id="ignore-directory", profile=_profile(oob=False), template_root=templates,
        config_root=cfg, engine_identity=_engine(), engine_pin="v3.11.0",
    )
    assert document["ignore"]["files"] == ["http"]
    assert document["ignore"]["resolved_files"] == ["http/ignored.yaml"]
    selected = {row["id"] for row in document["owners"][-1]["selected_templates"]}
    assert not selected & {"ignored-directory", "helper-directory", "github-directory"}


def test_ignore_wildcard_does_not_cross_directory_separator(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    (cfg / ".nuclei-ignore").write_text("tags: []\nfiles: [http/*/blocked.yaml]\n")
    shallow = templates / "http" / "one"
    deep = shallow / "two"
    deep.mkdir(parents=True)
    body = "info: {severity: high, tags: [cve]}\nhttp:\n- method: GET\n"
    (shallow / "blocked.yaml").write_text("id: shallow-blocked\n" + body)
    (deep / "blocked.yaml").write_text("id: deep-kept\n" + body)
    document = nuclei_policy.build_document(
        run_id="ignore-wildcard", profile=_profile(oob=False), template_root=templates,
        config_root=cfg, engine_identity=_engine(), engine_pin="v3.11.0",
    )
    assert document["ignore"]["resolved_files"] == ["http/one/blocked.yaml"]
    selected = {row["id"] for row in document["owners"][-1]["selected_templates"]}
    assert "shallow-blocked" not in selected
    assert "deep-kept" in selected
    assert nuclei_policy._engine_path_match("http/!/blocked.yaml", "http/[!a]/blocked.yaml")
    assert nuclei_policy._engine_path_match("http/a/blocked.yaml", "http/[!a]/blocked.yaml")
    assert not nuclei_policy._engine_path_match("http/b/blocked.yaml", "http/[!a]/blocked.yaml")
    assert not nuclei_policy._engine_path_match("http/a/blocked.yaml", "http/[a/blocked.yaml")


@pytest.mark.parametrize("template_body", [
    "headless:\n- steps: []\n",
    "code:\n- engine: [python3]\n  source: print(1)\n",
    "file:\n- extensions: [txt]\n",
    "self-contained: true\nhttp: []\n",
    "http:\n- fuzzing:\n  - part: query\n    type: replace\n",
])
def test_disabled_engine_load_capabilities_are_not_claimed_selected(
        tmp_path, fixed_settings, monkeypatch, template_body):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    (templates / "capability.yaml").write_text(
        "id: capability-gated\ninfo:\n  severity: high\n  tags: [cve]\n" + template_body
    )
    document = nuclei_policy.build_document(
        run_id="capability", profile=_profile(oob=False), template_root=templates,
        config_root=cfg, engine_identity=_engine(), engine_pin="v3.11.0",
    )
    assert "capability-gated" not in {
        row["id"] for row in document["owners"][-1]["selected_templates"]
    }


def test_duplicate_selected_template_ids_are_refused(tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    for name in ("duplicate-a", "duplicate-b"):
        (templates / f"{name}.yaml").write_text(
            "id: duplicate-id\ninfo:\n  severity: high\n  tags: [cve]\n"
            "http:\n- method: GET\n"
        )
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="duplicate template id"):
        nuclei_policy.build_document(
            run_id="duplicate", profile=_profile(oob=False), template_root=templates,
            config_root=cfg, engine_identity=_engine(), engine_pin="v3.11.0",
        )


def test_nested_template_ancestor_helper_is_bound(tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    nested = templates / "http" / "cves"
    nested.mkdir(parents=True)
    (templates / "http" / "payload.txt").write_text("one\ntwo\n")
    (nested / "helper.yaml").write_text(
        "id: ancestor-helper\ninfo:\n  severity: high\n  tags: [cve]\n"
        "http:\n- payloads:\n    value: ../payload.txt\n"
    )
    document = nuclei_policy.build_document(
        run_id="helper", profile=_profile(oob=False), template_root=templates, config_root=cfg,
        engine_identity=_engine(), engine_pin="v3.11.0",
    )
    assert "ancestor-helper" in {
        row["id"] for row in document["owners"][-1]["selected_templates"]
    }
    assert "http/payload.txt" in {row["path"] for row in document["helpers"]}


def test_inventory_refuses_oversize_descriptor_before_read(tmp_path, monkeypatch):
    path = tmp_path / "oversize.yaml"
    path.write_bytes(b"x" * 1024)
    original_read = nuclei_policy.os.read

    def guarded_read(fd, count):
        if nuclei_policy.os.readlink(f"/proc/self/fd/{fd}") == str(path):
            pytest.fail("oversize inventory file was read before descriptor-size admission")
        return original_read(fd, count)

    monkeypatch.setattr(nuclei_policy.os, "read", guarded_read)
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="byte bound"):
        nuclei_policy._file_row(tmp_path, path, byte_bound=100)


@pytest.mark.parametrize("server", [
    "https://oob.example/PRIVATE-CALLBACK-KEY",
    "https://oob.example:notaport",
    "oob.example:99999",
])
def test_oob_server_is_a_strict_secret_free_origin(server):
    with pytest.raises(nuclei_policy.NucleiPolicyError):
        nuclei_policy._freeze_oob_config({"callback_server": server})
    assert nuclei_policy._freeze_oob_config({"callback_server": "https://OOB.EXAMPLE/"}) == {
        "callback_server": "https://oob.example",
    }


def test_runtime_and_portable_schema_reject_same_engine_and_tree_shapes(
        tmp_path, fixed_settings, monkeypatch):
    jsonschema = pytest.importorskip("jsonschema")
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    document = nuclei_policy.build_document(
        run_id="schema-parity", profile=_profile(oob=False), template_root=templates,
        config_root=cfg, engine_identity=_engine(), engine_pin="v3.11.0",
    )
    schema = json.loads((Path(__file__).parents[1] / "release" / "evidence" / "schemas"
                         / "nuclei-policy-v1.schema.json").read_text())

    def redigest(changed):
        changed["policy_digest"] = None
        changed["policy_digest"] = nuclei_policy._sha256(nuclei_policy._canonical(changed))

    mutations = (
        lambda d: d["engine"]["identity"].update(attestation="unsupported-attestation"),
        lambda d: d["engine"]["identity"].update(closure={"bytes": -1, "objects": 0,
                                                           "sha256": "1" * 64}),
        lambda d: d["corpus"].pop("trust"),
        lambda d: d["config"].update(
            signature_verification="inventory-only-not-cryptographically-verified"),
    )
    for mutate in mutations:
        changed = json.loads(json.dumps(document))
        mutate(changed)
        redigest(changed)
        with pytest.raises(nuclei_policy.NucleiPolicyError):
            nuclei_policy.validate_document(changed)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(changed, schema)


def test_plan_reports_every_oob_owner_and_semantic_reference(monkeypatch):
    from click.testing import CliRunner

    summary = {
        "snapshot": "detached-tree",
        "corpus_trust": "unverified-inventory-only-not-an-authorship-claim",
        "modes": {"oob_backend": "off", "oob_enabled": False,
                  "block_private_targets": False},
        "owners": [
            {"owner": owner, "oob_backend": "off", "selected_count": 1,
             "semantic_counts": {"not_detected": 0, "potentially_state_changing": 1,
                                 "unknown": 0},
             "potentially_state_changing": [{"id": "risky", "path": "risky.yaml"}],
             "unknown": []}
            for owner in nuclei_policy.OWNERS
        ],
        "channels": [
            {"owner": "params.oob_probe", "enabled": False, "oob_backend": "off"},
            {"owner": "quarry.oob_poll", "enabled": False, "oob_backend": "off"},
            {"owner": "params.dalfox_blind_oob", "enabled": False, "oob_backend": "off"},
            {"owner": "quarry.oob_import", "enabled": True, "oob_backend": "local-only"},
        ],
    }
    profile = SimpleNamespace()
    monkeypatch.setattr(cli, "_resolve_profile", lambda value: value)
    monkeypatch.setattr(cli.TargetProfile, "load", lambda _value: profile)
    monkeypatch.setattr(nuclei_policy, "planning_summary", lambda _profile: summary)
    result = CliRunner().invoke(cli.cli, ["plan", "-t", "target.yaml"])
    assert result.exit_code == 0, result.output
    for owner in (*nuclei_policy.OWNERS, "params.oob_probe", "quarry.oob_poll",
                  "params.dalfox_blind_oob", "quarry.oob_import"):
        assert owner in result.output
    assert "oob=off" in result.output
    assert "risky@risky.yaml" in result.output
    assert "unverified-inventory-only-not-an-authorship-claim" in result.output


@pytest.mark.parametrize("template_request", [
    "http:\n- payloads:\n    value: missing-payload.txt\n",
    "http:\n- extractors:\n  - type: dsl\n    dsl: ['readFile(\"missing-helper.txt\")']\n",
])
def test_selected_template_unresolved_helper_reference_fails_closed(
        tmp_path, fixed_settings, monkeypatch, template_request):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    (templates / "broad.yaml").write_text(
        "id: unresolved\ninfo: {severity: high, tags: [cve]}\n" + template_request
    )
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="unresolved helper reference"):
        nuclei_policy.build_document(
            run_id="missing-helper", profile=_profile(oob=False), template_root=templates,
            config_root=cfg, engine_identity=_engine(),
        )


def test_selected_template_ambiguous_ancestor_helper_reference_fails_closed(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    nested = templates / "http" / "cves"
    nested.mkdir(parents=True)
    (templates / "http" / "payload.txt").write_text("parent\n")
    (nested / "payload.txt").write_text("near\n")
    (nested / "ambiguous.yaml").write_text(
        "id: ambiguous\ninfo: {severity: high, tags: [cve]}\n"
        "http:\n- payloads:\n    value: payload.txt\n"
    )
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="ambiguous helper reference"):
        nuclei_policy.build_document(
            run_id="ambiguous-helper", profile=_profile(oob=False), template_root=templates,
            config_root=cfg, engine_identity=_engine(),
        )


@pytest.mark.parametrize("server", ["oob.example", "OOB.EXAMPLE:443"])
def test_oob_origin_requires_an_explicit_http_scheme(server):
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="unsupported/secret URL parts"):
        nuclei_policy._freeze_oob_config({"callback_server": server})


def test_source_origin_is_separate_and_absent_tree_mutation_has_schema_runtime_parity(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    document = nuclei_policy.build_document(
        run_id="source-origin", profile=_profile(oob=False), template_root=templates,
        config_root=cfg, engine_identity=_engine(),
        template_source_state="detached-tree", config_source_state="detached-tree",
        template_source_origin_kind="tree", config_source_origin_kind="tree",
    )
    assert document["corpus"]["source_state"] == "detached-tree"
    assert document["corpus"]["source_origin_kind"] == "tree"
    changed = json.loads(json.dumps(document))
    changed["config"]["source_state"] = "absent"
    changed["policy_digest"] = None
    changed["policy_digest"] = nuclei_policy._sha256(nuclei_policy._canonical(changed))
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="contradictory source origin"):
        nuclei_policy.validate_document(changed)
    try:
        import jsonschema
    except ImportError:
        return
    schema = json.loads((Path(__file__).parents[1] / "release" / "evidence" / "schemas"
                         / "nuclei-policy-v1.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(changed, schema)


def test_validator_reconstructs_and_requires_the_complete_owner_selection(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    document = nuclei_policy.build_document(
        run_id="complete-selection", profile=_profile(oob=False), template_root=templates,
        config_root=cfg, engine_identity=_engine(),
    )
    changed = json.loads(json.dumps(document))
    owner = next(row for row in changed["owners"] if row["owner"] == "params.nuclei_takeover")
    owner["selected_templates"] = []
    owner["selected_count"] = 0
    owner["selection_digest"] = nuclei_policy._sha256(nuclei_policy._canonical([]))
    owner["protocol_partitions"] = nuclei_policy._protocol_partitions([])
    owner["semantic_inventory"] = {
        "classifier": "quarry.nuclei-semantic-risk.v1",
        "counts": {name: 0 for name in ("not_detected", "potentially_state_changing", "unknown")},
        "potentially_state_changing": [], "unknown": [],
    }
    changed["policy_digest"] = None
    changed["policy_digest"] = nuclei_policy._sha256(nuclei_policy._canonical(changed))
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="complete accepted selection"):
        nuclei_policy.validate_document(changed)


def test_all_oob_channels_are_explicit_and_dalfox_reuses_the_frozen_authority(
        tmp_path, fixed_settings, monkeypatch):
    token = "FROZEN-OOB-TOKEN-CANARY"
    templates, cfg = _corpus(tmp_path)
    profile = _profile(oob=True, blind=True)
    frozen = {"callback_server": "https://oob.example", "auth_token": token}
    document = nuclei_policy.build_document(
        run_id="all-channels", profile=profile, template_root=templates, config_root=cfg,
        engine_identity=_engine(), oob_config=frozen,
    )
    artifact = nuclei_policy._canonical(document)
    authority = nuclei_policy.Authority(
        document=document, path=tmp_path / "unused-policy", artifact_bytes=artifact,
        template_path=templates, config_path=cfg, template_check={}, config_check={},
        engine_identity=_engine(), oob_config=frozen,
    )
    assert all(row["oob_enabled"] and row["oob_backend"] == "self-hosted"
               and row["channel_digest"].startswith("sha256:") for row in document["owners"])
    assert [(row["owner"], row["enabled"], row["oob_backend"])
            for row in document["channels"]] == [
                ("params.oob_probe", True, "self-hosted"),
                ("quarry.oob_poll", True, "self-hosted"),
                ("params.dalfox_blind_oob", True, "self-hosted"),
                ("quarry.oob_import", True, "local-only"),
            ]
    monkeypatch.setattr(
        params.secrets, "oob", lambda: pytest.fail("Dalfox reread ambient OOB config"),
    )
    plan = params._blind_oob_plan(profile, authority)
    assert plan["origin"] == plan["server"] == "https://oob.example"
    assert plan["command_server"] == "oob.example"
    assert plan["secret"] == token
    assert plan["policy_digest"] == authority.digest
    monkeypatch.setattr(
        params, "_blind_oob_plan", lambda *_a, **_k: pytest.fail("command re-resolved OOB plan"),
    )
    command = params._dalfox_cmd("in", "out", profile, 1, oob_plan=plan)
    assert "--blind-oob=oob.example" in command
    assert token not in " ".join(command)


def test_quarry_probe_uses_frozen_channel_in_work_unit_and_event_without_reread(
        tmp_path, fixed_settings, monkeypatch):
    token = "PROBE-FROZEN-TOKEN"
    templates, cfg = _corpus(tmp_path)
    profile = _profile(oob=True, blind=True)
    frozen = {"callback_server": "https://oob.example", "auth_token": token}
    document = nuclei_policy.build_document(
        run_id="probe-channel", profile=profile, template_root=templates, config_root=cfg,
        engine_identity=_engine(), oob_config=frozen,
    )
    authority = nuclei_policy.Authority(
        document=document, path=tmp_path / "unused-policy",
        artifact_bytes=nuclei_policy._canonical(document), template_path=templates,
        config_path=cfg, template_check={}, config_check={}, engine_identity=_engine(),
        oob_config=frozen,
    )
    recorded, opened, emitted = [], {}, []

    class Run:
        def record(self, *args, **kwargs):
            recorded.append((args, kwargs))

        def add(self, *_args, **_kwargs):
            return True

    ctx = SimpleNamespace(run=Run(), nuclei_policy=authority, echo=lambda *_args: None)
    scope = SimpleNamespace(passive_only=False)
    monkeypatch.setattr(params, "have", lambda name: name == "interactsh-client")
    monkeypatch.setattr(params, "active_review_values", lambda *_args: [
        "https://target.example/path?url=http%3A%2F%2Fexample.invalid",
    ])
    monkeypatch.setattr(
        params.secrets, "oob", lambda: pytest.fail("Quarry probe reread ambient OOB config"),
    )
    monkeypatch.setattr(
        params.oob, "open_session",
        lambda _run, **kwargs: (opened.update(kwargs) or {"log": "raw/oob/log"}),
    )
    monkeypatch.setattr(
        params.oob, "resume_session", lambda *_args, **_kwargs: {"log": "raw/oob/log"},
    )
    monkeypatch.setattr(params.oob, "issue_token", lambda *_args, **_kwargs: "issued")
    monkeypatch.setattr(params.oob, "callback_url", lambda *_args, **_kwargs: "http://issued.oast")
    monkeypatch.setattr(params.oob, "poll_session", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(params.fetch, "redirect_location", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(params.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        params.events, "emit",
        lambda event, source_id, **fields: emitted.append((event, source_id, fields)) or {},
    )
    result = params._oob_probe(ctx, scope, profile)
    assert result is not None and opened == {
        "server": "https://oob.example", "token": token,
    }
    policy_event = next(fields for event, source, fields in emitted
                        if event == "oob_policy" and source == "params.oob_probe")
    assert policy_event["enabled"] is True and policy_event["oob_backend"] == "self-hosted"
    assert policy_event["policy_digest"] == authority.digest
    assert policy_event["work_unit"]


def _published_self_hosted_policy(tmp_path, fixed_settings):
    token = "CURRENT-FROZEN-TOKEN"
    templates, cfg = _corpus(tmp_path)
    profile = _profile(oob=True, blind=True)
    frozen = {"callback_server": "https://oob.example", "auth_token": token}
    document = nuclei_policy.build_document(
        run_id="poll-frozen", profile=profile, template_root=templates, config_root=cfg,
        engine_identity=_engine(), oob_config=frozen,
    )
    artifact = nuclei_policy._canonical(document)
    policy_path = tmp_path / "raw" / "nuclei-policy" / "policy.json"
    policy_path.parent.mkdir(parents=True)
    policy_path.write_bytes(artifact)
    authority = nuclei_policy.Authority(
        document=document, path=policy_path, artifact_bytes=artifact,
        template_path=templates, config_path=cfg, template_check={}, config_check={},
        engine_identity=_engine(), oob_config=frozen,
    )
    run = SimpleNamespace(
        run_id=document["run_id"], dir=tmp_path, manifest_path=tmp_path / "manifest.json",
        manifest_committed=lambda: True,
    )
    return profile, token, run, authority.manifest_summary()


@pytest.mark.parametrize("current", [
    {"callback_server": "https://other.example", "auth_token": "CURRENT-FROZEN-TOKEN"},
    {"callback_server": "https://oob.example", "auth_token": "DRIFTED-TOKEN"},
])
def test_oob_poll_refuses_server_or_token_drift_before_resume(
        tmp_path, fixed_settings, monkeypatch, current):
    profile, _token, run, summary = _published_self_hosted_policy(tmp_path, fixed_settings)
    profile.target, profile.path = "example", tmp_path / "target.yaml"
    monkeypatch.setattr(cli.TargetProfile, "load", lambda _path: profile)
    monkeypatch.setattr(cli, "_resolve_profile", lambda value: value)
    monkeypatch.setattr(cli, "_existing_run", lambda *_args: run)
    monkeypatch.setattr(run_manifest, "read", lambda _path: SimpleNamespace(document={
        "profile": {"oob_enabled": True, "nuclei_policy": summary},
    }))
    monkeypatch.setattr(cli.secrets, "oob", lambda: dict(current))
    monkeypatch.setattr(
        oob, "resume_session", lambda *_a, **_k: pytest.fail("drifted poll contacted a backend"),
    )
    with pytest.raises(exit_contract.Refused, match="do not authenticate the frozen channel"):
        cli._oob_poll(str(profile.path), run.run_id, 0, {})


def test_oob_poll_passes_only_authenticated_frozen_server_and_token(
        tmp_path, fixed_settings, monkeypatch):
    profile, token, run, summary = _published_self_hosted_policy(tmp_path, fixed_settings)
    profile.target, profile.path = "example", tmp_path / "target.yaml"
    monkeypatch.setattr(cli.TargetProfile, "load", lambda _path: profile)
    monkeypatch.setattr(cli, "_resolve_profile", lambda value: value)
    monkeypatch.setattr(cli, "_existing_run", lambda *_args: run)
    monkeypatch.setattr(run_manifest, "read", lambda _path: SimpleNamespace(document={
        "profile": {"oob_enabled": True, "nuclei_policy": summary},
    }))
    monkeypatch.setattr(cli.secrets, "oob", lambda: {
        "callback_server": "https://oob.example", "auth_token": token,
    })
    captured = {}

    def resume(_run, **kwargs):
        captured.update(kwargs)
        return None

    monkeypatch.setattr(oob, "resume_session", resume)
    with pytest.raises(Exception, match="no resumable OOB session"):
        cli._oob_poll(str(profile.path), run.run_id, 0, {})
    assert captured == {
        "token": token, "server": "https://oob.example",
        "wait": 0,
        "expected_server": "https://oob.example",
    }


def test_resume_expected_server_mismatch_returns_before_binary_or_launch(
        tmp_path, monkeypatch):
    run = store.Run.create(tmp_path, "example.test", run_id="oob-server-mismatch")
    monkeypatch.setattr(oob, "load_session", lambda _run: {
        "session_file": "/tmp/session", "server": "https://old.example",
    })
    monkeypatch.setattr(
        oob.shutil, "which", lambda _name: pytest.fail("mismatch queried a launch dependency"),
    )
    assert oob.resume_session(
        run, server="https://frozen.example", expected_server="https://frozen.example",
    ) is None


def test_resume_refuses_a_nonrepository_adapter_before_launch(monkeypatch):
    monkeypatch.setattr(
        oob, "load_session",
        lambda _run: pytest.fail("nonrepository adapter reached session loading"),
    )
    with pytest.raises(ContractError, match="exact repository run"):
        oob.resume_session(object(), wait=0)


@pytest.mark.parametrize(("mixed", "marker"), [
    (False, False), (False, True), (True, False), (True, True),
])
def test_javascript_is_explicitly_load_excluded_regardless_of_unverified_signature_marker(
        tmp_path, fixed_settings, monkeypatch, mixed, marker):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    path = templates / f"javascript-{'mixed' if mixed else 'pure'}-{'marker' if marker else 'unsigned'}.yaml"
    path.write_text(
        "id: javascript-candidate\ninfo: {severity: high, tags: [cve]}\n"
        + ("http: []\n" if mixed else "")
        + "javascript:\n- code: |\n    template: true\n"
        + ("# digest: forged-unverified-marker\n" if marker else "")
    )
    document = nuclei_policy.build_document(
        run_id="javascript-excluded", profile=_profile(oob=False), template_root=templates,
        config_root=cfg, engine_identity=_engine(), engine_pin="v3.11.0",
    )
    inventory = next(row for row in document["template_inventory"] if row["path"] == path.name)
    assert inventory["load_state"] == "load-excluded"
    assert inventory["required_capabilities"] == ["javascript"]
    assert inventory["signature_state"] == (
        "digest-marker-present-unverified" if marker else "unsigned"
    )
    assert all(path.name not in {row["path"] for row in owner["selected_templates"]}
               for owner in document["owners"])
    assert all(owner["flags"].count("-ept") == 1
               and owner["flags"][owner["flags"].index("-ept") + 1] == "javascript"
               for owner in document["owners"])
    nuclei_policy.validate_document(document)
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((Path(__file__).parents[1] / "release" / "evidence" / "schemas"
                         / "nuclei-policy-v1.schema.json").read_text())
    jsonschema.validate(document, schema)


def _settlement_authority(tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    document = nuclei_policy.build_document(
        run_id="settlement", profile=_profile(oob=False), template_root=templates,
        config_root=cfg, engine_identity=_engine(), engine_pin="v3.11.0",
    )
    authority = nuclei_policy.Authority(
        document=document, path=tmp_path / "unused-policy",
        artifact_bytes=nuclei_policy._canonical(document), template_path=templates,
        config_path=cfg, template_check={}, config_check={}, engine_identity=_engine(),
    )
    authority.assert_ready = lambda: None
    return authority


def _started_identity(document):
    return {
        "tool": "nuclei",
        "identities": [{**_engine(), "role": "adapter"}],
        "dynamic_closure": [{
            "role": "nuclei-templates",
            "sha256": document["corpus"]["digest"].removeprefix("sha256:"),
        }],
        "private_inputs": [{
            "kind": "tree", "role": "nuclei-config",
            "source_state": document["config"]["source_state"],
            "closure": {
                "bytes": document["config"]["bytes"],
                "files": document["config"]["file_count"],
                "sha256": document["config"]["digest"].removeprefix("sha256:"),
            },
        }],
    }


@pytest.mark.parametrize("started", [False, True])
def test_settlement_binds_owner_coverage_for_started_and_non_started_results(
        tmp_path, fixed_settings, monkeypatch, started):
    authority = _settlement_authority(tmp_path, fixed_settings, monkeypatch)
    emitted = []
    monkeypatch.setattr(
        nuclei_policy.events, "emit",
        lambda event, source_id, **fields: emitted.append((event, source_id, fields)) or {},
    )
    owner_name = "params.nuclei_scan"
    row = authority.owner(owner_name)
    meta = {"started": started}
    if started:
        meta.update(runtime_identity=_started_identity(authority.document),
                    runtime_identity_ref="raw/runtime-identities/launch.json")
    result = SimpleNamespace(meta=meta, started=started,
                             status=SimpleNamespace(value="success"))
    authority.settle(owner_name, result, input_total=3, work_unit="work-unit")
    event, source_id, fields = emitted[-1]
    assert (event, source_id) == ("nuclei_policy_finish", owner_name)
    assert fields["selection_digest"] == row["selection_digest"]
    assert fields["flags_digest"] == row["flags_digest"]
    assert fields["selected_count"] == row["selected_count"]
    assert fields["started"] is started


def test_settlement_protocol_lane_must_match_the_executed_command(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    (templates / "tcp.yaml").write_text(
        "id: tcp-only\ninfo: {severity: high, tags: [cve]}\n"
        "tcp:\n- host: ['{{Hostname}}']\n"
    )
    document = nuclei_policy.build_document(
        run_id="settlement-lane", profile=_profile(oob=False), template_root=templates,
        config_root=cfg, engine_identity=_engine(), engine_pin="v3.11.0",
    )
    authority = nuclei_policy.Authority(
        document=document, path=tmp_path / "unused-policy",
        artifact_bytes=nuclei_policy._canonical(document), template_path=templates,
        config_path=cfg, template_check={}, config_check={}, engine_identity=_engine(),
    )
    authority.assert_ready = lambda: None
    row = authority.owner("params.nuclei_scan")
    result = SimpleNamespace(
        cmd=["nuclei", "-l", "/input", "-jsonl", "-o", "/output",
             "-pt", "http,dns", *row["flags"]],
        meta={"started": False}, started=False,
        status=SimpleNamespace(value="success"),
    )
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="differs from the executed"):
        authority.settle(
            "params.nuclei_scan", result, input_total=1, work_unit="work-unit",
            protocol_lane="tcp",
        )


def test_settlement_validates_owner_before_any_authority_reconciliation(
        tmp_path, fixed_settings, monkeypatch):
    authority = _settlement_authority(tmp_path, fixed_settings, monkeypatch)
    authority.assert_ready = lambda: pytest.fail("unknown owner reached authority reconciliation")
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="owner is absent"):
        authority.settle(
            "not-a-nuclei-owner", SimpleNamespace(meta={"started": False}),
            input_total=0, work_unit="none",
        )


@pytest.mark.parametrize("mutation", ["missing", "forged", "swapped"])
def test_started_settlement_rejects_missing_forged_or_swapped_private_config_closure(
        tmp_path, fixed_settings, monkeypatch, mutation):
    authority = _settlement_authority(tmp_path, fixed_settings, monkeypatch)
    identity = _started_identity(authority.document)
    if mutation == "missing":
        identity["private_inputs"] = []
    elif mutation == "forged":
        identity["private_inputs"][0]["closure"]["bytes"] += 1
    else:
        identity["private_inputs"][0]["closure"]["sha256"] = (
            authority.document["corpus"]["digest"].removeprefix("sha256:")
        )
    result = SimpleNamespace(
        meta={"started": True, "runtime_identity": identity,
              "runtime_identity_ref": "raw/runtime-identities/launch.json"},
        started=True, status=SimpleNamespace(value="success"),
    )
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="config"):
        authority.settle("params.nuclei_scan", result, input_total=1, work_unit="work-unit")


def test_persisted_nuclei_config_closure_contains_no_path_or_secret_material(
        tmp_path, fixed_settings, monkeypatch):
    home = tmp_path / "home"
    _templates, cfg = _corpus(home)
    executable = tmp_path / "bin" / "nuclei"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    tool = registry.Tool(bin="nuclei", phase="params", role="fixture", policy="distro",
                         env_allow=["NUCLEI_CONFIG_DIR", "NUCLEI_TEMPLATES_DIR"])
    token = "PRIVATE-RUNTIME-CLOSURE-CANARY"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("NUCLEI_CONFIG", str(cfg))
    monkeypatch.setenv("PATH", str(executable.parent))
    monkeypatch.setattr(registry, "tool_for_bin", lambda name: tool if name == "nuclei" else None)
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {
        "callback_server": "https://oob.example", "auth_token": token,
    })
    run = store.Run.create(tmp_path / "project", "acme.example", run_id="config-closure")
    run.write_state("running")
    ctx = PhaseContext(run=run, profile=_profile(), scope=SimpleNamespace(), workdir=run.dir / "work")
    with nuclei_policy.run_authority(ctx) as authority:
        row = authority.owner("params.nuclei_scan")
        with authority.oob_flags() as flags:
            command = ["nuclei", "-l", "/tmp/in", "-jsonl", "-o", "/tmp/out",
                       *row["flags"]]
            # oob_flags repeats the public -iserver pair already bound in owner.flags; append only the
            # private file transport created for the frozen token.
            if "-config" in flags:
                command += ["-config", flags[flags.index("-config") + 1]]
            prepared = runtime_identity.prepare_launch("nuclei", command)
            try:
                config_input = next(item for item in prepared.record["private_inputs"]
                                    if item["role"] == "nuclei-config")
                assert set(config_input) == {"kind", "role", "source_state", "closure"}
                assert set(config_input["closure"]) == {"bytes", "files", "sha256"}
                assert config_input["closure"] == {
                    "bytes": authority.document["config"]["bytes"],
                    "files": authority.document["config"]["file_count"],
                    "sha256": authority.document["config"]["digest"].removeprefix("sha256:"),
                }
                serialized = json.dumps(prepared.record, sort_keys=True)
                assert token not in serialized and str(cfg) not in serialized
                authority.settle(
                    "params.nuclei_scan",
                    SimpleNamespace(
                        meta={"started": True, "runtime_identity": prepared.record,
                              "runtime_identity_ref": "raw/runtime-identities/launch.json"},
                        started=True, status=SimpleNamespace(value="success"),
                    ),
                    input_total=1, work_unit="actual-private-config-closure",
                )
            finally:
                prepared.close()


@pytest.mark.parametrize("field", [
    "corpus_digest", "config_digest", "ignore_digest", "corpus_trust",
    "corpus_source_origin_kind", "config_source_origin_kind", "owners",
])
def test_published_document_reconciles_every_manifest_policy_projection(
        tmp_path, fixed_settings, monkeypatch, field):
    _profile_obj, _token, run, summary = _published_self_hosted_policy(
        tmp_path, fixed_settings,
    )
    changed = json.loads(json.dumps(summary))
    if field == "owners":
        changed[field] = changed[field][:-1]
    else:
        changed[field] = "sealed-self-consistent-lie"
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="manifest and published"):
        nuclei_policy.published_document(run, changed)


def test_published_document_rejects_manifest_artifact_alias_before_any_read(
        tmp_path, fixed_settings, monkeypatch):
    _profile_obj, _token, run, summary = _published_self_hosted_policy(
        tmp_path, fixed_settings,
    )
    summary = json.loads(json.dumps(summary))
    summary["artifact"] = "raw/nuclei-policy/other.json"
    monkeypatch.setattr(
        nuclei_policy, "_regular_bytes",
        lambda *_args, **_kwargs: pytest.fail("noncanonical manifest artifact was read"),
    )
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="artifact reference"):
        nuclei_policy.published_document(run, summary)


def test_load_exclusion_state_has_runtime_and_portable_schema_parity(
        tmp_path, fixed_settings, monkeypatch):
    monkeypatch.setattr(nuclei_policy.secrets, "oob", lambda: {})
    templates, cfg = _corpus(tmp_path)
    (templates / "javascript.yaml").write_text(
        "id: javascript\ninfo: {severity: high, tags: [cve]}\n"
        "javascript:\n- code: |\n    template: true\n"
    )
    document = nuclei_policy.build_document(
        run_id="load-state-parity", profile=_profile(oob=False), template_root=templates,
        config_root=cfg, engine_identity=_engine(), engine_pin="v3.11.0",
    )
    changed = json.loads(json.dumps(document))
    next(row for row in changed["template_inventory"]
         if row["path"] == "javascript.yaml")["load_state"] = "loaded"
    changed["policy_digest"] = None
    changed["policy_digest"] = nuclei_policy._sha256(nuclei_policy._canonical(changed))
    with pytest.raises(nuclei_policy.NucleiPolicyError, match="load exclusion"):
        nuclei_policy.validate_document(changed)
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((Path(__file__).parents[1] / "release" / "evidence" / "schemas"
                         / "nuclei-policy-v1.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(changed, schema)
