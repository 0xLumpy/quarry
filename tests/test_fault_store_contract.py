"""Focused checks for the non-promoting C-FAULT-STORE source contract."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

from quarry_recon import fault_store_evidence as fault_store
from quarry_recon import release_contracts as contracts


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.offline
_CANDIDATE = "sha256:" + "a" * 64
_SPEC = importlib.util.spec_from_file_location(
    "emit_fault_store_source_plan",
    ROOT / "scripts" / "emit_fault_store_source_plan.py",
)
assert _SPEC and _SPEC.loader
producer = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(producer)


def _inputs() -> dict[str, bytes]:
    return {
        name: (ROOT / path).read_bytes()
        for name, path in fault_store.INPUT_PATHS.items()
    }


@pytest.fixture(scope="module")
def source_plan() -> tuple[dict, dict[str, bytes]]:
    bodies = _inputs()
    return fault_store.build_source_plan(
        candidate_identity_digest=_CANDIDATE,
        input_bodies=bodies,
    ), bodies


def test_committed_case_manifest_is_the_exact_canonical_source_roster():
    raw = (ROOT / fault_store.INPUT_PATHS["fault-store-case-manifest"]).read_bytes()
    document = fault_store.read_case_manifest(raw)
    assert raw == fault_store.canonical_case_manifest_bytes()
    assert document["case_count"] == fault_store.CASE_COUNT == 9
    assert document["node_count"] == fault_store.NODE_COUNT == 60
    assert [case["boundary"] for case in document["cases"]] == [
        "write",
        "flush",
        "fsync",
        "rename",
        "manifest",
        "event-sink",
        "reopen",
        "seal",
        "close",
    ]
    nodeids = [nodeid for case in document["cases"] for nodeid in case["nodeids"]]
    assert len(nodeids) == len(set(nodeids)) == 60
    assert all(
        nodeid.startswith("tests/") and "::test_" in nodeid for nodeid in nodeids
    )
    assert document["disposition"] == "source_substrate"
    assert document["closure_status"] == "OPEN"
    assert document["semantic_promotion"] is False


def test_source_plan_binds_exact_candidate_inputs_but_claims_no_execution(source_plan):
    document, bodies = source_plan
    encoded = fault_store.canonical_source_plan_bytes(
        document,
        candidate_identity_digest=_CANDIDATE,
        input_bodies=bodies,
    )
    assert (
        fault_store.read_source_plan(
            encoded,
            candidate_identity_digest=_CANDIDATE,
            input_bodies=bodies,
        )
        == document
    )
    assert document["case_count"] == 9 and document["node_count"] == 60
    assert all(case["execution_status"] == "not_executed" for case in document["cases"])
    assert all(case["outcome_digest"] is None for case in document["cases"])
    assert document["attestation"] == {
        "required_lane": "H0-hermetic",
        "execution_claimed": False,
        "signed": False,
        "h0_isolated": False,
        "candidate_ownership_authenticated": False,
        "collection_interval_authenticated": False,
        "toolchain_authenticated": False,
    }
    with pytest.raises(fault_store.FaultStoreEvidenceError, match="non-promoting"):
        fault_store.read_source_plan(
            encoded,
            candidate_identity_digest=_CANDIDATE,
            input_bodies=bodies,
            accepting=True,
        )
    assert "C-FAULT-STORE" not in contracts.SEMANTIC_VERIFIERS
    assert "C-FAULT-STORE" not in contracts.PROVISIONAL_SEMANTIC_VERIFIERS
    assert contracts.REQUIRED_ARTIFACTS["C-FAULT-STORE"] == (
        ("fault-matrix", "application/json"),
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "candidate",
        "manifest",
        "binding",
        "case-order",
        "case-node",
        "execution",
        "outcome",
        "promotion",
        "numeric-promotion",
        "float-count",
        "attestation",
        "unknown",
    ],
)
def test_manual_reader_rejects_substitution_and_promotion(source_plan, mutation):
    document, bodies = source_plan
    changed = copy.deepcopy(document)
    if mutation == "candidate":
        changed["candidate_identity_digest"] = "sha256:" + "b" * 64
    elif mutation == "manifest":
        changed["case_manifest_digest"] = "sha256:" + "b" * 64
    elif mutation == "binding":
        changed["input_bindings"][0]["digest"] = "sha256:" + "b" * 64
    elif mutation == "case-order":
        changed["cases"][0], changed["cases"][1] = (
            changed["cases"][1],
            changed["cases"][0],
        )
    elif mutation == "case-node":
        changed["cases"][0]["nodeids"][0] += "-invented"
    elif mutation == "execution":
        changed["cases"][0]["execution_status"] = "passed"
    elif mutation == "outcome":
        changed["cases"][0]["outcome_digest"] = "sha256:" + "c" * 64
    elif mutation == "promotion":
        changed["semantic_promotion"] = True
    elif mutation == "numeric-promotion":
        changed["semantic_promotion"] = 0
    elif mutation == "float-count":
        changed["case_count"] = 9.0
    elif mutation == "attestation":
        changed["attestation"]["signed"] = True
    else:
        changed["claim"] = "pass"
    with pytest.raises(fault_store.FaultStoreEvidenceError):
        fault_store.verify_source_plan(
            changed,
            candidate_identity_digest=_CANDIDATE,
            input_bodies=bodies,
        )


def test_schema_and_manual_shape_contracts_are_exact(source_plan):
    jsonschema = pytest.importorskip("jsonschema")
    document, bodies = source_plan
    manifest = fault_store.case_manifest_document()
    manifest_schema = json.loads(
        (
            ROOT / fault_store.INPUT_PATHS["fault-store-case-manifest-schema"]
        ).read_bytes()
    )
    plan_schema = json.loads(
        (ROOT / fault_store.INPUT_PATHS["fault-store-source-plan-schema"]).read_bytes()
    )
    manifest_validator = jsonschema.Draft202012Validator(manifest_schema)
    plan_validator = jsonschema.Draft202012Validator(plan_schema)
    assert list(manifest_validator.iter_errors(manifest)) == []
    assert list(plan_validator.iter_errors(document)) == []
    assert len(manifest_schema["properties"]["cases"]["prefixItems"]) == 9
    assert manifest_schema["properties"]["cases"]["items"] is False
    assert len(plan_schema["properties"]["cases"]["prefixItems"]) == 9
    assert plan_schema["properties"]["cases"]["items"] is False
    assert len(plan_schema["properties"]["input_bindings"]["prefixItems"]) == len(
        fault_store.INPUT_PATHS
    )

    malformed = []
    reordered = copy.deepcopy(manifest)
    reordered["cases"][0], reordered["cases"][1] = (
        reordered["cases"][1],
        reordered["cases"][0],
    )
    malformed.append((reordered, manifest_validator))
    numeric_manifest = copy.deepcopy(manifest)
    numeric_manifest["semantic_promotion"] = 0
    malformed.append((numeric_manifest, manifest_validator))
    promoted = copy.deepcopy(document)
    promoted["semantic_promotion"] = True
    malformed.append((promoted, plan_validator))
    executed = copy.deepcopy(document)
    executed["cases"][0]["execution_status"] = "passed"
    malformed.append((executed, plan_validator))
    newline = copy.deepcopy(document)
    newline["candidate_identity_digest"] += "\n"
    malformed.append((newline, plan_validator))
    for changed, validator in malformed:
        assert list(validator.iter_errors(changed)), changed

    raw = fault_store.canonical_source_plan_bytes(
        document,
        candidate_identity_digest=_CANDIDATE,
        input_bodies=bodies,
    )
    huge = raw.replace(
        b'"case_count":9', b'"case_count":999999999999999999999999999999'
    )
    with pytest.raises(fault_store.FaultStoreEvidenceError):
        fault_store.read_source_plan(
            huge,
            candidate_identity_digest=_CANDIDATE,
            input_bodies=bodies,
        )
    nested = b"[" * 2048 + b"0" + b"]" * 2048 + b"\n"
    with pytest.raises(fault_store.FaultStoreEvidenceError):
        fault_store.read_source_plan(
            nested,
            candidate_identity_digest=_CANDIDATE,
            input_bodies=bodies,
        )

    numeric_manifest_raw = fault_store._canonical(numeric_manifest)
    with pytest.raises(fault_store.FaultStoreEvidenceError):
        fault_store.read_case_manifest(numeric_manifest_raw)


def test_producer_emits_only_canonical_non_promoting_outputs(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    plan_path = tmp_path / "plan.json"
    assert (
        producer.main(
            [
                "--candidate-identity-digest",
                _CANDIDATE,
                "--case-manifest-output",
                str(manifest_path),
                "--source-plan-output",
                str(plan_path),
            ]
        )
        == 0
    )
    bodies = _inputs()
    assert manifest_path.read_bytes() == fault_store.canonical_case_manifest_bytes()
    document = fault_store.read_source_plan(
        plan_path.read_bytes(),
        candidate_identity_digest=_CANDIDATE,
        input_bodies=bodies,
    )
    assert document["attestation"]["execution_claimed"] is False
