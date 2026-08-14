from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

from quarry_recon import run_manifest, settle, state, store


pytestmark = pytest.mark.offline


def _committed_run(tmp_path: Path, *, entity: bool = True) -> store.Run:
    run = store.Run.create(tmp_path, "manifest.example")
    run.write_state("running")
    if entity:
        assert run.add("subdomain", {"host": "www.manifest.example"})
    run.write_manifest({"profile": "test"}, ["horizontal"])
    return run


def _rewrite(path: Path, mutate, *, canonical: bool = True) -> None:
    document = json.loads(path.read_text())
    mutate(document)
    raw = run_manifest.canonical_json_bytes(document) if canonical else json.dumps(document).encode()
    path.write_bytes(raw)


def test_writer_emits_one_canonical_reconciled_v1_manifest(tmp_path):
    run = _committed_run(tmp_path)
    parsed = run_manifest.read(run.manifest_path)

    assert parsed.raw == run_manifest.canonical_json_bytes(parsed.document)
    assert parsed.document["schema_version"] == run_manifest.SCHEMA_VERSION
    assert parsed.document["lifecycle"] == {
        "generation": run.generation(), "state_at_commit": "finalizing",
    }
    assert parsed.document["entity_counts"] == {"subdomain": 1}
    assert [record["path"] for record in parsed.document["base_files"]] == sorted(
        [record["path"] for record in parsed.document["base_files"]], key=lambda value: value.encode(),
    )
    assert {record["path"] for record in parsed.document["base_files"]} == {
        "normalized/subdomain.jsonl", "run.json",
    }
    assert run.manifest_committed()
    assert settle._committed(run.dir) == parsed.summary


@pytest.mark.parametrize(
    "mutate, fragment",
    [
        (lambda doc: doc.__setitem__("unknown", True), "extra keys"),
        (lambda doc: doc.__setitem__("schema_version", "quarry.run-manifest.v99"), "schema_version"),
        (lambda doc: doc["entity_counts"].__setitem__("subdomain", 2), "entity_counts"),
        (lambda doc: doc["summary"].__setitem__("tools_failed", True), "tools_failed"),
        (lambda doc: doc["summary"].__setitem__("verdict", "complete_with_gaps"), "contradicts"),
        (lambda doc: doc["lifecycle"].__setitem__("generation", "wrong"), "generation"),
        (lambda doc: doc["base_files"][0].__setitem__("digest", "sha256:" + "f" * 64), "base_files"),
    ],
)
def test_semantic_manifest_corruption_refuses_every_consumer(tmp_path, mutate, fragment):
    run = _committed_run(tmp_path)
    _rewrite(run.manifest_path, mutate)

    with pytest.raises(run_manifest.ManifestError, match=fragment):
        run_manifest.read(run.manifest_path)
    reopened = store.Run.open(tmp_path, "manifest.example", run.run_id)
    assert not reopened.manifest_committed()
    with pytest.raises(state.ContractError):
        reopened.summary()
    assert settle._committed(run.dir) is None


def test_noncanonical_and_duplicate_member_encodings_are_not_commitments(tmp_path):
    run = _committed_run(tmp_path)
    original = json.loads(run.manifest_path.read_text())
    run.manifest_path.write_text(json.dumps(original, indent=2))
    assert not run.manifest_committed()

    raw = run_manifest.canonical_json_bytes(original)
    run.manifest_path.write_bytes(raw[:-2] + b',"run_id":"duplicate"}\n')
    assert not run.manifest_committed()
    with pytest.raises(run_manifest.ManifestError, match="duplicated"):
        run_manifest.read(run.manifest_path)


@pytest.mark.parametrize("name", ["run.json", "normalized/subdomain.jsonl"])
def test_mutating_any_bound_base_file_invalidates_the_manifest(tmp_path, name):
    run = _committed_run(tmp_path)
    target = run.dir / name
    target.write_bytes(target.read_bytes() + (b"{}\n" if name.endswith(".jsonl") else b" "))

    with pytest.raises(run_manifest.ManifestError, match="base_files|identity|entity_counts"):
        run_manifest.read(run.manifest_path)
    assert settle._committed(run.dir) is None


def test_unknown_normalized_log_and_nonregular_base_objects_fail_closed(tmp_path):
    run = _committed_run(tmp_path)
    (run.normalized / "unknown.jsonl").write_text("{}\n")
    with pytest.raises(run_manifest.ManifestError, match="base_files|unknown entity|mode"):
        run_manifest.read(run.manifest_path)

    (run.normalized / "unknown.jsonl").unlink()
    os.symlink("subdomain.jsonl", run.normalized / "alias.jsonl")
    with pytest.raises(run_manifest.ManifestError, match="not a regular file"):
        run_manifest.build_file_inventory(run.dir)


def test_raw_tool_bytes_are_bound_without_being_reinterpreted_as_control_json(tmp_path):
    from quarry_recon import privfs

    run = store.Run.create(tmp_path, "manifest.example")
    run.write_state("running")
    raw = run.raw_path("probe", "fixture", "malformed.jsonl")
    privfs.write_private(raw, "{ deliberately malformed raw evidence\n")
    run.write_manifest({"profile": "test"}, ["probe"])

    parsed = run_manifest.read(run.manifest_path)
    descriptor = next(record for record in parsed.document["base_files"]
                      if record["path"] == "raw/probe/fixture/malformed.jsonl")
    assert descriptor["media_type"] == "application/octet-stream" and descriptor["rows"] is None


def test_manifest_tool_rows_must_equal_the_bound_ledger(tmp_path):
    run = _committed_run(tmp_path)

    def mutate(document):
        document["tool_runs"].append({
            "phase": "probe", "tool": "invented", "status": "ok", "exit_code": 0,
            "duration": 0, "stdout_lines": 0, "note": "", "cmd": "invented",
            "stderr_tail": "", "cpu_s": 0, "peak_rss_mb": 0, "depends_on": "",
        })

    _rewrite(run.manifest_path, mutate)
    with pytest.raises(run_manifest.ManifestError, match="tool_runs"):
        run_manifest.read(run.manifest_path)


def test_lifecycle_identity_is_verified_by_authoritative_consumers(tmp_path):
    run = _committed_run(tmp_path)
    lifecycle = json.loads(run.state_path.read_text())
    lifecycle["generation"] = "different"
    run.state_path.write_text(json.dumps(lifecycle))

    # The manifest object itself is still a committed immutable base object.
    assert run_manifest.read(run.manifest_path, verify_lifecycle=False)
    with pytest.raises(run_manifest.ManifestError, match="generation"):
        run_manifest.read(run.manifest_path)
    assert settle._committed(run.dir) is None


def test_summary_records_are_exact_not_permissively_downcast(tmp_path):
    run = _committed_run(tmp_path)

    def mutate(document):
        document["summary"]["faults"].append({
            "kind": "diagnostic", "where": "test", "detail": "x",
            "challenges_completeness": False, "ignored": "not allowed",
        })

    _rewrite(run.manifest_path, mutate)
    with pytest.raises(run_manifest.ManifestError, match="Fault"):
        run_manifest.read(run.manifest_path)


@pytest.mark.parametrize("value", [("not", "json"), {1: "coerced key"}, "\ud800"])
def test_direct_validator_rejects_values_canonical_json_would_coerce_or_cannot_encode(tmp_path, value):
    run = _committed_run(tmp_path)
    document = json.loads(run.manifest_path.read_text())
    document["profile"] = {"value": value}
    with pytest.raises(run_manifest.ManifestError):
        run_manifest.validate_document(document)


def test_schema_structural_surface_matches_the_runtime_contract():
    from quarry_recon import envelope

    schema_path = Path("release/evidence/schemas/run-manifest-v1.schema.json")
    schema = json.loads(schema_path.read_text())
    assert schema["properties"]["schema_version"] == {"const": run_manifest.SCHEMA_VERSION}
    assert set(schema["properties"]) == run_manifest._TOP_LEVEL_REQUIRED | run_manifest._TOP_LEVEL_OPTIONAL
    assert set(schema["properties"]["entity_counts"]["propertyNames"]["enum"]) == set(store.ENTITY_KEYS)
    assert {
        name: rule["const"] for name, rule in schema["properties"]["envelope"]["properties"].items()
    } == envelope.declaration()
    assert schema["$defs"]["count"]["maximum"] == run_manifest.MAX_JSON_INTEGER
    assert schema["properties"]["base_files"]["maxItems"] == run_manifest.MAX_BASE_FILES
    assert "Structural envelope only" in schema["$comment"]
    assert schema["additionalProperties"] is False


def test_file_descriptor_generation_is_deterministic(tmp_path):
    run = _committed_run(tmp_path)
    first = copy.deepcopy(run_manifest.build_file_inventory(run.dir))
    second = run_manifest.build_file_inventory(run.dir)
    assert first == second


def test_broken_lifecycle_symlink_is_unsafe_presence_not_legacy_absence(tmp_path):
    run = _committed_run(tmp_path)
    run.state_path.unlink()
    os.symlink("missing-state", run.state_path)

    assert not run.manifest_committed()
    assert store.Run.open(tmp_path, run.target, run.run_id).state == "unknown"
    with pytest.raises(run_manifest.ManifestError):
        run_manifest.read(run.manifest_path)


@pytest.mark.parametrize(
    "relative,is_directory",
    [
        ("manifest.json", False),
        ("run.json", False),
        ("state.json", False),
        ("normalized/subdomain.jsonl", False),
        ("normalized", True),
    ],
)
def test_manifest_reader_authenticates_private_modes(tmp_path, relative, is_directory):
    run = _committed_run(tmp_path)
    os.chmod(run.dir / relative, 0o755 if is_directory else 0o644)

    with pytest.raises(run_manifest.ManifestError, match="mode"):
        run_manifest.read(run.manifest_path)
    assert not run.manifest_committed()


def test_generation_is_derived_not_a_mutually_forged_label(tmp_path):
    run = _committed_run(tmp_path)
    _rewrite(run.manifest_path, lambda doc: doc["lifecycle"].__setitem__("generation", "a" * 16))
    lifecycle = json.loads(run.state_path.read_text())
    lifecycle["generation"] = "a" * 16
    run.state_path.write_text(json.dumps(lifecycle))
    os.chmod(run.state_path, 0o600)

    with pytest.raises(run_manifest.ManifestError, match="generation"):
        run_manifest.read(run.manifest_path)


def test_envelope_is_the_exact_supported_declaration_not_a_fold_control(tmp_path):
    run = _committed_run(tmp_path)

    def mutate(document):
        document["envelope"]["max_keys_per_entity"] = 0
        document["entity_counts"] = {}

    _rewrite(run.manifest_path, mutate)
    with pytest.raises(run_manifest.ManifestError, match="envelope"):
        run_manifest.read(run.manifest_path)


def test_summary_projections_are_recomputed_from_authenticated_logs(tmp_path):
    run = _committed_run(tmp_path)

    def mutate(document):
        document["summary"]["tool_status"] = {"failed": 99}
        document["summary"]["provider_spend"] = [{
            "lane": "provider", "provider": "fixture", "measure": "credits",
            "amount": 5, "unknown": 0,
        }]

    _rewrite(run.manifest_path, mutate)
    with pytest.raises(run_manifest.ManifestError, match="tool_status|provider_spend"):
        run_manifest.read(run.manifest_path)


@pytest.mark.parametrize(
    "mutate,fragment",
    [
        (lambda summary: summary["coverage"].append({
            "source_id": "fixture", "measure": "items", "eligible": 0, "tested": 0,
            "omitted": 0, "reason": None, "valid": True, "by_kind": [], "units": [],
            "unknown": [],
        }), "by_kind"),
        (lambda summary: summary["gaps"].append({"phase": None, "tool": None, "why": None}),
         "phase"),
        (lambda summary: summary["faults"].append({
            "kind": "diagnostic", "where": 7, "detail": 8,
            "challenges_completeness": False,
        }), "where"),
        (lambda summary: summary["gaps"].append({
            "phase": "fixture", "tool": "fixture", "why": "x", "priority": "critical",
        }), "priority"),
    ],
)
def test_nested_contract_faults_are_typed_manifest_refusals(tmp_path, mutate, fragment):
    run = _committed_run(tmp_path)
    document = json.loads(run.manifest_path.read_text())
    mutate(document["summary"])
    with pytest.raises(run_manifest.ManifestError, match=fragment):
        run_manifest.validate_document(document)


def test_base_artifact_roots_have_fixed_file_and_directory_kinds(tmp_path):
    run = _committed_run(tmp_path, entity=False)
    run.raw.rmdir()
    run.raw.write_bytes(b"not a directory")
    os.chmod(run.raw, 0o600)
    with pytest.raises(run_manifest.ManifestError, match="directory root"):
        run_manifest.build_file_inventory(run.dir)

    run.raw.unlink()
    run.raw.mkdir(mode=0o700)
    (run.dir / "events.jsonl").mkdir(mode=0o700)
    with pytest.raises(run_manifest.ManifestError, match="file root"):
        run_manifest.build_file_inventory(run.dir)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda state_doc: state_doc.__setitem__("extra", True),
        lambda state_doc: state_doc.__setitem__("updated", {"not": "a timestamp"}),
        lambda state_doc: state_doc.__setitem__("detail", 99),
        lambda state_doc: state_doc["stages"].__setitem__("report", "done"),
        lambda state_doc: state_doc.update({"state": "finalization_failed", "stages": {}, "detail": None}),
    ],
)
def test_lifecycle_sidecar_has_one_strict_semantic_contract(tmp_path, mutate):
    run = _committed_run(tmp_path)
    state_doc = json.loads(run.state_path.read_text())
    mutate(state_doc)
    run.state_path.write_text(json.dumps(state_doc))
    os.chmod(run.state_path, 0o600)
    with pytest.raises(run_manifest.ManifestError):
        run_manifest.read(run.manifest_path)
    assert store.Run.open(tmp_path, run.target, run.run_id).state == "unknown"


def test_versionless_no_state_manifest_uses_explicit_legacy_reader(tmp_path):
    run = _committed_run(tmp_path)
    document = json.loads(run.manifest_path.read_text())
    for name in ("schema_version", "lifecycle", "base_files"):
        del document[name]
    run.manifest_path.write_bytes(run_manifest.canonical_json_bytes(document))
    run.state_path.unlink()

    legacy = run_manifest.read_legacy(run.manifest_path)
    assert legacy.summary == document["summary"]
    assert run_manifest.legacy_committed(run.manifest_path)
    reopened = store.Run.open(tmp_path, run.target, run.run_id)
    assert reopened.manifest_committed() and reopened.state == "finished"
    assert reopened.summary() == document["summary"]


@pytest.mark.parametrize(
    "status_value,exit_code",
    [
        ("victory", 73),
        ("success", "zero"),
    ],
)
def test_tool_terminal_vocabulary_and_exit_type_are_closed(tmp_path, status_value, exit_code):
    run = _committed_run(tmp_path)
    document = json.loads(run.manifest_path.read_text())
    document["tool_runs"].append({
        "phase": "fixture", "tool": "fixture", "status": status_value,
        "exit_code": exit_code, "duration": 0, "stdout_lines": 0, "note": "",
        "cmd": "fixture", "stderr_tail": "", "cpu_s": 0, "peak_rss_mb": 0,
        "depends_on": "",
    })
    with pytest.raises(run_manifest.ManifestError, match="status|exit"):
        run_manifest.validate_document(document)


@pytest.mark.parametrize("status_value,exit_code", [("failed", 0), ("success", 1)])
def test_status_is_authoritative_when_exit_alone_cannot_explain_it(status_value, exit_code):
    record = store.ToolRunRecord(
        phase="fixture", tool="fixture", status=status_value, exit_code=exit_code,
        duration=0, stdout_lines=1, note="", cmd="fixture",
    )
    assert (record.status, record.exit_code) == (status_value, exit_code)


def test_unknown_provider_terminal_is_refused_before_manifest_publication(tmp_path):
    from quarry_recon import privfs

    run = store.Run.create(tmp_path, "manifest.example")
    run.write_state("running")
    privfs.write_private(
        run.dir / "events.jsonl",
        json.dumps({
            "event": "tool_finish", "source_id": "provider.fixture", "provider": True,
            "status": "victory", "work_unit": "u", "exit_code": 73,
        }) + "\n",
    )
    with pytest.raises(run_manifest.ManifestError, match="status"):
        run.write_manifest({"profile": "test"}, ["fixture"])
    assert not os.path.lexists(run.manifest_path)


def test_manifest_projection_never_materializes_evidence_snapshot(tmp_path):
    from quarry_recon import privfs

    run = store.Run.create(tmp_path, "manifest.example")
    run.write_state("running")
    privfs.write_private(run.raw_path("probe", "fixture", "secret.bin"), "TOP-SECRET-EVIDENCE")
    run.add("secret", {"value": "AKIA-FULL-DISCOVERED-SECRET", "kind": "aws"})
    run.write_manifest({"profile": "test"}, ["fixture"])
    before = set(Path("/tmp").glob("quarry-run-manifest-*"))
    assert run_manifest.read(run.manifest_path)
    assert set(Path("/tmp").glob("quarry-run-manifest-*")) == before
    assert not hasattr(run_manifest, "_authenticated_snapshot")


def test_writer_refuses_a_manifest_above_the_reader_bound(tmp_path):
    run = store.Run.create(tmp_path, "manifest.example")
    run.write_state("running")
    profile = {"blob": "x" * (run_manifest.MAX_MANIFEST_BYTES + 1)}
    with pytest.raises(run_manifest.ManifestError, match="exceeds"):
        run.write_manifest(profile, ["fixture"])
    assert not os.path.lexists(run.manifest_path)


def test_provider_flag_is_an_exact_boolean_before_projection(tmp_path):
    from quarry_recon import privfs

    run = store.Run.create(tmp_path, "manifest.example")
    run.write_state("running")
    privfs.write_private(
        run.dir / "events.jsonl",
        json.dumps({
            "event": "tool_finish", "source_id": "provider.fixture", "provider": 1,
            "status": "victory", "work_unit": "u", "exit_code": 73,
        }) + "\n",
    )
    with pytest.raises(run_manifest.ManifestError, match="provider"):
        run.write_manifest({"profile": "test"}, ["fixture"])
    assert not os.path.lexists(run.manifest_path)


def test_malformed_provider_start_cannot_disappear_into_a_complete_verdict(tmp_path):
    from quarry_recon import privfs

    run = store.Run.create(tmp_path, "manifest.example")
    run.write_state("running")
    privfs.write_private(
        run.dir / "events.jsonl",
        json.dumps({
            "event": "tool_start", "source_id": "provider.fixture", "provider": True,
            "work_unit": [],
        }) + "\n",
    )
    with pytest.raises(run_manifest.ManifestError, match="work_unit"):
        run.write_manifest({"profile": "test"}, ["fixture"])
    assert not os.path.lexists(run.manifest_path)


def test_nonboolean_provider_reset_cannot_erase_a_failed_terminal(tmp_path):
    from quarry_recon import privfs

    run = store.Run.create(tmp_path, "manifest.example")
    run.write_state("running")
    rows = [
        {
            "event": "tool_finish", "source_id": "provider.fixture", "provider": True,
            "work_unit": "old", "status": "failed", "exit_code": 1,
        },
        {
            "event": "tool_start", "source_id": "provider.fixture", "provider": True,
            "work_unit": "new", "reset_generation": "false",
        },
        {
            "event": "tool_finish", "source_id": "provider.fixture", "provider": True,
            "work_unit": "new", "status": "success", "exit_code": 0,
        },
    ]
    privfs.write_private(
        run.dir / "events.jsonl", "".join(json.dumps(row) + "\n" for row in rows),
    )
    with pytest.raises(run_manifest.ManifestError, match="reset_generation"):
        run.write_manifest({"profile": "test"}, ["fixture"])
    assert not os.path.lexists(run.manifest_path)


@pytest.mark.parametrize(("status_value", "kind"), [("timed_out", "timeout"), ("blocked", "unknown")])
def test_every_degraded_provider_terminal_gates_the_committed_verdict(
    tmp_path, status_value, kind,
):
    from quarry_recon import privfs

    run = store.Run.create(tmp_path, "manifest.example")
    run.write_state("running")
    rows = [
        {
            "event": "tool_start", "source_id": "provider.fixture", "provider": True,
            "work_unit": "u", "reset_generation": True,
        },
        {
            "event": "tool_finish", "source_id": "provider.fixture", "provider": True,
            "work_unit": "u", "status": status_value, "exit_code": None,
        },
    ]
    privfs.write_private(
        run.dir / "events.jsonl", "".join(json.dumps(row) + "\n" for row in rows),
    )
    run.write_manifest({"profile": "test"}, ["fixture"])
    summary = run_manifest.read(run.manifest_path).summary
    assert summary["verdict"] == "complete_with_gaps"
    assert summary["tool_status"] == {status_value: 1}
    assert [(gap["status"], gap["kind"]) for gap in summary["gaps"]] == [(status_value, kind)]


def test_limited_tool_result_is_a_committed_operator_limit(tmp_path):
    from quarry_recon.runner import RunResult, Status

    run = store.Run.create(tmp_path, "manifest.example")
    run.record(
        "fixture",
        RunResult(
            "fixture", ["fixture"], Status.LIMITED, 0, 0.1, None, 0,
            note="operator cap",
        ),
    )
    run.write_manifest({"profile": "test"}, ["fixture"])
    summary = run_manifest.read(run.manifest_path).summary
    assert summary["verdict"] == "complete_with_limits"
    assert summary["tool_status"] == {"limited": 1}
    assert summary["operator_limits"] == [{
        "phase": "fixture", "tool": "fixture", "why": "operator cap",
        "status": "limited", "output_lines": 0, "origin": "operator",
    }]


@pytest.mark.parametrize(
    "event",
    [
        {"event": "spend", "source_id": [], "provider": "fixture", "measure": "credits",
         "amount": 1},
        {"event": "remainder", "source_id": [], "unit": "u", "measure": "items",
         "model": "project_progress"},
    ],
)
def test_projection_event_identity_cannot_disappear_from_the_manifest(tmp_path, event):
    from quarry_recon import privfs

    run = store.Run.create(tmp_path, "manifest.example")
    run.write_state("running")
    privfs.write_private(run.dir / "events.jsonl", json.dumps(event) + "\n")
    with pytest.raises(run_manifest.ManifestError, match="source_id"):
        run.write_manifest({"profile": "test"}, ["fixture"])
    assert not os.path.lexists(run.manifest_path)


def test_malformed_remainder_is_explicitly_gapped_not_clean(tmp_path):
    from quarry_recon import privfs

    run = store.Run.create(tmp_path, "manifest.example")
    run.write_state("running")
    privfs.write_private(
        run.dir / "events.jsonl",
        json.dumps({
            "event": "remainder", "source_id": "vertical.wildcard_http",
            "unit": "vertical.wildcard_http:targets", "measure": "targets",
            "model": "invented", "retriable": {"now": 1, "cooldown": 0},
            "terminal": {},
        }) + "\n",
    )
    run.write_manifest({"profile": "test"}, ["vertical"])
    summary = run_manifest.read(run.manifest_path).summary
    assert summary["verdict"] == "complete_with_gaps"
    assert summary["remainders"][0]["invalid"]
    assert [(gap["status"], gap["kind"]) for gap in summary["gaps"]] == [
        ("remainder:unknown", "unknown"),
    ]


def test_event_sink_degradation_cannot_be_bound_to_a_clean_summary(tmp_path):
    from quarry_recon import privfs

    run = _committed_run(tmp_path)
    degraded = {"writes_failed": 1, "first_error": "OSError: lost event"}
    privfs.write_private(run.dir / "events.degraded.json", json.dumps(degraded))
    document = json.loads(run.manifest_path.read_text())
    document["observability_degraded"] = degraded
    document["base_files"] = run_manifest.build_file_inventory(run.dir)
    run.manifest_path.write_bytes(run_manifest.canonical_json_bytes(document))

    with pytest.raises(run_manifest.ManifestError, match="completeness-challenging fault"):
        run_manifest.read(run.manifest_path)


def test_envelope_degradation_cannot_be_bound_to_a_clean_summary(tmp_path):
    from quarry_recon import privfs

    run = _committed_run(tmp_path)
    degraded = {"ledger:subdomain": "EXCEPTION: refusal ledger lost"}
    privfs.write_private(
        run.dir / "envelope-degraded.json", json.dumps({"degraded": degraded}),
    )
    document = json.loads(run.manifest_path.read_text())
    document["envelope_degraded"] = degraded
    document["base_files"] = run_manifest.build_file_inventory(run.dir)
    run.manifest_path.write_bytes(run_manifest.canonical_json_bytes(document))

    with pytest.raises(run_manifest.ManifestError, match="manifest.notes"):
        run_manifest.read(run.manifest_path)


@pytest.mark.parametrize(
    ("eligible", "tested", "omitted"),
    [("1", "1", "0"), (True, True, False)],
)
def test_coverage_counters_are_never_coerced_before_commitment(
    tmp_path, eligible, tested, omitted,
):
    from quarry_recon import privfs

    run = store.Run.create(tmp_path, "manifest.example")
    run.write_state("running")
    privfs.write_private(
        run.dir / "events.jsonl",
        json.dumps({
            "event": "coverage_partial", "source_id": "probe.fixture",
            "unit": "u", "measure": "items", "kind": "cap",
            "eligible": eligible, "tested": tested, "omitted": omitted,
            "coverage_valid": True,
        }) + "\n",
    )
    with pytest.raises(run_manifest.ManifestError, match="eligible"):
        run.write_manifest({"profile": "test"}, ["fixture"])
    assert not os.path.lexists(run.manifest_path)


def test_partial_coverage_counters_cannot_disappear_without_an_eligible_denominator(tmp_path):
    from quarry_recon import privfs

    run = store.Run.create(tmp_path, "manifest.example")
    run.write_state("running")
    privfs.write_private(
        run.dir / "events.jsonl",
        json.dumps({
            "event": "coverage_partial", "source_id": "probe.fixture",
            "unit": "u", "measure": "items", "kind": "cap",
            "tested": 1, "omitted": 0,
        }) + "\n",
    )
    with pytest.raises(run_manifest.ManifestError, match="without eligible"):
        run.write_manifest({"profile": "test"}, ["fixture"])
    assert not os.path.lexists(run.manifest_path)


def test_transient_normalized_bytes_cannot_escape_the_authenticated_fold(tmp_path, monkeypatch):
    run = _committed_run(tmp_path)
    path = run.normalized / "subdomain.jsonl"
    original = path.read_bytes()
    replacement = original.replace(b"www.manifest.example", b"bad.manifest.example")
    assert replacement != original
    fold = run_manifest._fold_entities_at

    def transient(root_fd, document):
        path.write_bytes(replacement)
        os.chmod(path, 0o600)
        try:
            return fold(root_fd, document)
        finally:
            path.write_bytes(original)
            os.chmod(path, 0o600)

    monkeypatch.setattr(run_manifest, "_fold_entities_at", transient)
    with pytest.raises(run_manifest.ManifestError, match="changed|base_files"):
        run_manifest.read(run.manifest_path)


def test_projector_consumes_the_exact_bound_event_bytes(tmp_path, monkeypatch):
    from quarry_recon import privfs

    run = store.Run.create(tmp_path, "manifest.example")
    run.write_state("running")
    privfs.write_private(
        run.dir / "events.jsonl",
        json.dumps({
            "event": "spend", "source_id": "provider.fixture", "provider": "fixture",
            "measure": "credits", "amount": 5,
        }) + "\n",
    )
    run.write_manifest({}, ["fixture"])
    read_file = run_manifest._read_file_at

    def transient(root_fd, relative, *args, **kwargs):
        if relative == "events.jsonl":
            return b"{}\n"
        return read_file(root_fd, relative, *args, **kwargs)

    monkeypatch.setattr(run_manifest, "_read_file_at", transient)
    with pytest.raises(run_manifest.ManifestError, match="events.jsonl|base_files"):
        run_manifest.read(run.manifest_path)


def test_manifest_control_name_is_rechecked_after_projection(tmp_path, monkeypatch):
    run = _committed_run(tmp_path)
    reconcile = run_manifest._reconcile_repository

    def mutate_after(*args, **kwargs):
        reconcile(*args, **kwargs)
        run.manifest_path.write_bytes(b"{}\n")
        os.chmod(run.manifest_path, 0o600)

    monkeypatch.setattr(run_manifest, "_reconcile_repository", mutate_after)
    with pytest.raises(run_manifest.ManifestError, match="manifest.json changed"):
        run_manifest.read(run.manifest_path)
