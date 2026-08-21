"""Focused bounded C-SOURCE-REGISTRY reconciliation substrate checks."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from quarry_recon import release_contracts as contracts
from quarry_recon import source_registry_evidence as registry


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.offline
_CANDIDATE = "sha256:" + "a" * 64


def _inputs() -> dict[str, bytes]:
    return {name: (ROOT / path).read_bytes() for name, path in registry._INPUT_PATHS.items()}


def _artifact() -> tuple[dict, dict[str, bytes]]:
    bodies = _inputs()
    return registry.build(candidate_identity_digest=_CANDIDATE, input_bodies=bodies), bodies


def test_reconciliation_is_canonical_complete_and_execution_free():
    artifact, bodies = _artifact()
    encoded = registry.canonical_json_bytes(artifact)
    assert registry.read(encoded, candidate_identity_digest=_CANDIDATE, input_bodies=bodies) == artifact
    assert artifact["counts"] == {
        "planned_contract_count": 67, "auxiliary_contract_count": 25,
        "canonical_contract_count": 92, "planned_door_count": 67,
        "auxiliary_door_count": 24, "transport_door_count": 91, "ownership_count": 92,
    }
    assert artifact["local_event_without_transport"] == ["evidence.ownership"]
    assert artifact["h0_static_emitter"]["executed_lane_count"] == 0
    assert artifact["h1_synthetic_admission"]["executed_lane_count"] == 0




@pytest.mark.parametrize("name", [
    "docs-policy-sources-registry", "docs-policy-sources-module",
    "docs-policy-ownership-policy", "docs-policy-transport-doors",
])
def test_reconciliation_rejects_each_authoritative_input_digest_mutation(name):
    artifact, bodies = _artifact()
    mutated = dict(bodies)
    mutated[name] += b"# mutation\n"
    with pytest.raises(registry.SourceRegistryEvidenceError, match="digest drift"):
        registry.verify(artifact, input_bodies=mutated)


@pytest.mark.parametrize("mutation", ["auxiliary", "door", "special", "literal", "dynamic", "h1", "nodeid", "selection"])
def test_reconciliation_rejects_omission_unknown_and_partition_mutations(mutation):
    artifact, _bodies = _artifact()
    changed = copy.deepcopy(artifact)
    if mutation == "auxiliary":
        changed["contracts"] = [row for row in changed["contracts"] if row["section"] != "auxiliary"]
    elif mutation == "door":
        changed["doors"].pop()
    elif mutation == "special":
        changed["local_event_without_transport"] = []
    elif mutation == "literal":
        changed["h0_static_emitter"]["literal_source_ids"].append("unknown.literal")
    elif mutation == "dynamic":
        changed["h0_static_emitter"]["finite_dynamic_maps"][0]["source_ids"].append("unknown.dynamic")
    elif mutation == "nodeid":
        changed["h0_static_emitter"]["receipt"]["nodeid"] = "tests/other.py::test_forged"
    elif mutation == "selection":
        changed["h1_synthetic_admission"]["receipt"]["selection"]["selected"] = 2
    else:
        changed["h1_synthetic_admission"]["admissions"].pop()
    with pytest.raises(registry.SourceRegistryEvidenceError):
        registry.verify(changed)


def test_reconciliation_binds_candidate_and_promoted_semantic_contract():
    artifact, _bodies = _artifact()
    with pytest.raises(registry.SourceRegistryEvidenceError, match="another candidate"):
        registry.verify(artifact, candidate_identity_digest="sha256:" + "b" * 64)
    assert contracts.REQUIRED_ARTIFACTS["C-SOURCE-REGISTRY"] == (
        ("registry-reconciliation", "application/json"),
    )
    assert contracts.SEMANTIC_VERIFIERS["C-SOURCE-REGISTRY"] is contracts._semantic_source_registry
    assert set(contracts._SOURCE_REGISTRY_BINDINGS) == set(registry._INPUT_PATHS)


def test_schema_and_reader_reject_the_same_receipt_and_probe_shape_mutations():
    validator_module = pytest.importorskip("jsonschema")
    artifact, _bodies = _artifact()
    schema = json.loads((ROOT / "release/evidence/schemas/source-registry-reconciliation-v1.schema.json").read_bytes())
    validator = validator_module.Draft202012Validator(schema)
    for mutate in (
        lambda item: item["h0_static_emitter"]["receipt"].pop("selection"),
        lambda item: item["h1_synthetic_admission"]["receipt"]["selection"].update(selected=2),
        lambda item: item["h1_synthetic_admission"]["admissions"][0]["synthetic_probe"].update(value={}),
    ):
        changed = copy.deepcopy(artifact)
        mutate(changed)
        assert list(validator.iter_errors(changed))
        with pytest.raises(registry.SourceRegistryEvidenceError):
            registry.verify(changed)
