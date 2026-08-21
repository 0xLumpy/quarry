"""Focused C-PATH-IDENTITY source/evidence substrate checks."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

from quarry_recon import path_identity_evidence as path_identity
from quarry_recon import release_contracts as contracts


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.offline
_CANDIDATE = "sha256:" + "a" * 64
_SPEC = importlib.util.spec_from_file_location(
    "emit_path_identity_evidence",
    ROOT / "scripts" / "emit_path_identity_evidence.py",
)
assert _SPEC and _SPEC.loader
producer = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(producer)


def _inputs() -> dict[str, bytes]:
    return {
        name: (ROOT / path).read_bytes()
        for name, path in path_identity.INPUT_PATHS.items()
    }


@pytest.fixture(scope="module")
def collected() -> tuple[dict, dict[str, bytes]]:
    bodies = _inputs()
    document = path_identity.build_containment_decisions(
        candidate_identity_digest=_CANDIDATE,
        input_bodies=bodies,
    )
    return document, bodies


def test_property_corpus_is_exact_candidate_independent_canonical_roster():
    body = (ROOT / path_identity.INPUT_PATHS["path-identity-corpus"]).read_bytes()
    document = path_identity.read_property_corpus(body)
    assert body == path_identity.canonical_property_corpus_bytes()
    assert document["disposition"] == "source_substrate"
    assert document["closure_status"] == "OPEN"
    assert len(document["cases"]) == path_identity.CASE_COUNT == 96
    assert len({case["case_id"] for case in document["cases"]}) == 96
    assert "candidate_identity_digest" not in document
    assert {case["subject"] for case in document["cases"]} == {
        "project", "run", "campaign", "tool", "artifact", "private_path", "entity",
    }


def test_collector_invokes_full_roster_and_records_zero_mutation(collected):
    document, bodies = collected
    encoded = path_identity.canonical_containment_decisions_bytes(
        document,
        candidate_identity_digest=_CANDIDATE,
        input_bodies=bodies,
    )
    assert path_identity.read_containment_decisions(
        encoded,
        candidate_identity_digest=_CANDIDATE,
        input_bodies=bodies,
    ) == document
    assert document["case_count"] == 96
    assert [row["case_id"] for row in document["cases"]] == [
        row["case_id"] for row in path_identity.PROPERTY_CASES
    ]
    for row in document["cases"]:
        assert row["actual_disposition"] == row["expected_disposition"]
        assert row["mutation_count"] == 0
        assert row["tree_before"] == row["tree_after"]
        assert row["identity_before"] == row["identity_after"]
        assert row["cache_before"] == row["cache_after"]
    runtime_entity_cases = document["cases"][-4:]
    assert [row["operation"] for row in runtime_entity_cases] == [
        "run_entity_read", "run_entity_read", "run_entity_add", "run_entity_add",
    ]
    assert all(row["cache_before"]["run_locks"] == 1 for row in runtime_entity_cases)
    assert all(
        row["cache_before"][name] == 0
        for row in runtime_entity_cases
        for name in ("record_entities", "folded_entities", "count_entities")
    )


def test_raw_observations_are_self_unattested_and_require_the_release_adapter(collected):
    document, _bodies = collected
    assert document["disposition"] == "source_substrate"
    assert document["closure_status"] == "OPEN"
    assert document["semantic_promotion"] is False
    assert document["attestation"] == {
        "required_lane": "H0-hermetic",
        "collection_context": "local-unattested",
        "signed": False,
        "h0_isolated": False,
        "candidate_ownership_authenticated": False,
        "collection_interval_authenticated": False,
        "toolchain_authenticated": False,
    }
    assert contracts.SEMANTIC_VERIFIERS["C-PATH-IDENTITY"] is \
        contracts._semantic_path_identity
    assert "C-PATH-IDENTITY" not in contracts.PROVISIONAL_SEMANTIC_VERIFIERS
    assert contracts.REQUIRED_ARTIFACTS["C-PATH-IDENTITY"] == (
        ("containment-decisions", "application/json"),
        ("property-corpus", "application/json"),
    )


@pytest.mark.parametrize("mutation", [
    "candidate", "case-order", "case-result", "case-omission", "tree", "cache",
    "exception", "timestamp", "large-integer", "unknown-field", "promotion",
])
def test_manual_reader_rejects_fabricated_or_incomplete_decisions(collected, mutation):
    document, bodies = collected
    changed = copy.deepcopy(document)
    if mutation == "candidate":
        changed["candidate_identity_digest"] = "sha256:" + "b" * 64
    elif mutation == "case-order":
        changed["cases"][0], changed["cases"][1] = changed["cases"][1], changed["cases"][0]
    elif mutation == "case-result":
        changed["cases"][0]["actual_disposition"] = "refused"
    elif mutation == "case-omission":
        changed["cases"].pop()
    elif mutation == "tree":
        changed["cases"][0]["tree_after"]["digest"] = "sha256:" + "b" * 64
    elif mutation == "cache":
        changed["cases"][0]["cache_after"]["run_locks"] += 1
    elif mutation == "exception":
        refused = next(row for row in changed["cases"] if row["exception"] is not None)
        refused["exception"]["class"] = "builtins.ValueError"
    elif mutation == "timestamp":
        changed["collection_interval"]["finished_at"] = "2026-08-21T00:00:00+00:00"
    elif mutation == "large-integer":
        changed["cases"][0]["tree_after"]["entries"] = 1 << 63
    elif mutation == "unknown-field":
        changed["cases"][0]["claim"] = "pass"
    else:
        changed["semantic_promotion"] = True
    with pytest.raises(path_identity.PathIdentityEvidenceError):
        path_identity.verify_containment_decisions(
            changed,
            candidate_identity_digest=_CANDIDATE,
            input_bodies=bodies,
        )


def test_schema_and_manual_readers_reject_the_same_shape_mutations(collected):
    validator_module = pytest.importorskip("jsonschema")
    document, bodies = collected
    decisions_schema = json.loads((
        ROOT / "release/evidence/schemas/path-identity-containment-decisions-v1.schema.json"
    ).read_bytes())
    corpus_schema = json.loads((
        ROOT / "release/evidence/schemas/path-identity-property-corpus-v1.schema.json"
    ).read_bytes())
    decisions_validator = validator_module.Draft202012Validator(decisions_schema)
    corpus_validator = validator_module.Draft202012Validator(corpus_schema)
    corpus = path_identity.property_corpus_document()
    assert corpus_schema["$defs"]["text"]["not"] == {"pattern": "[^ -~]"}
    assert decisions_schema["$defs"]["text"]["not"] == {"pattern": "[^ -~]"}
    assert decisions_schema["$defs"]["digest"]["minLength"] == \
        decisions_schema["$defs"]["digest"]["maxLength"] == 71
    assert decisions_schema["$defs"]["timestamp"]["minLength"] == \
        decisions_schema["$defs"]["timestamp"]["maxLength"] == 27
    assert len(decisions_schema["properties"]["cases"]["prefixItems"]) == 96
    assert decisions_schema["properties"]["cases"]["items"] is False
    assert len(corpus_schema["properties"]["cases"]["prefixItems"]) == 96
    assert corpus_schema["properties"]["cases"]["items"] is False
    assert list(decisions_validator.iter_errors(document)) == []
    assert list(corpus_validator.iter_errors(corpus)) == []

    mutations = []
    unknown = copy.deepcopy(document)
    unknown["unexpected"] = None
    mutations.append(unknown)
    bad_time = copy.deepcopy(document)
    bad_time["collection_interval"]["started_at"] = "2026-08-21T00:00:00Z"
    mutations.append(bad_time)
    bad_integer = copy.deepcopy(document)
    bad_integer["cases"][0]["tree_before"]["entries"] = 1 << 63
    mutations.append(bad_integer)
    missing = copy.deepcopy(document)
    missing["cases"].pop()
    mutations.append(missing)
    reordered = copy.deepcopy(document)
    reordered["cases"][0], reordered["cases"][1] = reordered["cases"][1], reordered["cases"][0]
    mutations.append(reordered)
    wrong_id = copy.deepcopy(document)
    wrong_id["cases"][0]["case_id"] = "substituted-case"
    mutations.append(wrong_id)
    wrong_operation = copy.deepcopy(document)
    wrong_operation["cases"][0]["operation"] = "validate_entity"
    mutations.append(wrong_operation)
    wrong_subject = copy.deepcopy(document)
    wrong_subject["cases"][0]["subject"] = "entity"
    mutations.append(wrong_subject)
    wrong_expected = copy.deepcopy(document)
    wrong_expected["cases"][0]["expected_disposition"] = "refused"
    mutations.append(wrong_expected)
    wrong_exception_class = copy.deepcopy(document)
    refused_index = next(
        index for index, row in enumerate(wrong_exception_class["cases"])
        if row["exception"] is not None
    )
    wrong_exception_class["cases"][refused_index]["exception"]["class"] = "builtins.ValueError"
    mutations.append(wrong_exception_class)
    accepted_with_refusal = copy.deepcopy(document)
    refused_row = next(row for row in document["cases"] if row["exception"] is not None)
    accepted_with_refusal["cases"][0]["exception"] = copy.deepcopy(refused_row["exception"])
    accepted_with_refusal["cases"][0]["return_value"] = None
    mutations.append(accepted_with_refusal)
    refused_with_return = copy.deepcopy(document)
    refused_with_return["cases"][refused_index]["exception"] = None
    refused_with_return["cases"][refused_index]["return_value"] = copy.deepcopy(
        document["cases"][0]["return_value"]
    )
    mutations.append(refused_with_return)
    unicode_text = copy.deepcopy(document)
    unicode_text["environment"]["platform_release"] = "å" * 300
    mutations.append(unicode_text)
    for changed in mutations:
        assert list(decisions_validator.iter_errors(changed))
        with pytest.raises(path_identity.PathIdentityEvidenceError):
            path_identity.verify_containment_decisions(
                changed,
                candidate_identity_digest=_CANDIDATE,
                input_bodies=bodies,
            )

    corpus_mutations = []
    changed_corpus = copy.deepcopy(corpus)
    changed_corpus["cases"][0]["unexpected"] = None
    corpus_mutations.append(changed_corpus)
    reordered_corpus = copy.deepcopy(corpus)
    reordered_corpus["cases"][0], reordered_corpus["cases"][1] = \
        reordered_corpus["cases"][1], reordered_corpus["cases"][0]
    corpus_mutations.append(reordered_corpus)
    wrong_corpus_id = copy.deepcopy(corpus)
    wrong_corpus_id["cases"][0]["case_id"] = "substituted-case"
    corpus_mutations.append(wrong_corpus_id)
    wrong_corpus_operation = copy.deepcopy(corpus)
    wrong_corpus_operation["cases"][0]["operation"] = "validate_entity"
    corpus_mutations.append(wrong_corpus_operation)
    wrong_corpus_input = copy.deepcopy(corpus)
    wrong_corpus_input["cases"][0]["input"]["value"] = "another"
    corpus_mutations.append(wrong_corpus_input)
    wrong_corpus_expected = copy.deepcopy(corpus)
    wrong_corpus_expected["cases"][0]["expected_exception"] = "builtins.ValueError"
    corpus_mutations.append(wrong_corpus_expected)
    for changed in corpus_mutations:
        assert list(corpus_validator.iter_errors(changed))
        with pytest.raises(path_identity.PathIdentityEvidenceError):
            path_identity.read_property_corpus(path_identity._canonical_line(changed))


def test_reader_rejects_huge_integer_float_and_nonfinite_tokens_before_shape_validation(collected):
    document, bodies = collected
    encoded = path_identity.canonical_containment_decisions_bytes(
        document,
        candidate_identity_digest=_CANDIDATE,
        input_bodies=bodies,
    )
    needle = b'"case_count":96'
    assert needle in encoded
    for replacement in (
        b'"case_count":' + b"9" * 5000,
        b'"case_count":96.0',
        b'"case_count":NaN',
    ):
        malformed = encoded.replace(needle, replacement, 1)
        with pytest.raises(path_identity.PathIdentityEvidenceError):
            path_identity.read_containment_decisions(
                malformed,
                candidate_identity_digest=_CANDIDATE,
                input_bodies=bodies,
            )


@pytest.mark.parametrize("mutation", ["text", "digest", "timestamp"])
def test_schema_and_manual_reader_reject_terminal_newline_values(collected, mutation):
    validator_module = pytest.importorskip("jsonschema")
    document, bodies = collected
    schema = json.loads((
        ROOT / "release/evidence/schemas/path-identity-containment-decisions-v1.schema.json"
    ).read_bytes())
    validator = validator_module.Draft202012Validator(schema)
    changed = copy.deepcopy(document)
    if mutation == "text":
        changed["environment"]["platform_release"] = "safe\n"
    elif mutation == "digest":
        changed["candidate_identity_digest"] += "\n"
    else:
        changed["collection_interval"]["finished_at"] += "\n"
    assert list(validator.iter_errors(changed))
    with pytest.raises(path_identity.PathIdentityEvidenceError):
        path_identity.verify_containment_decisions(
            changed,
            candidate_identity_digest=_CANDIDATE,
            input_bodies=bodies,
        )


def test_each_bound_source_substitution_is_rejected(collected):
    document, bodies = collected
    for name in sorted(path_identity.INPUT_PATHS):
        changed = dict(bodies)
        changed[name] += b"\nsubstitution"
        with pytest.raises(path_identity.PathIdentityEvidenceError):
            path_identity.verify_containment_decisions(
                document,
                candidate_identity_digest=_CANDIDATE,
                input_bodies=changed,
            )


def test_producer_emits_exact_corpus_and_parseable_local_decisions(tmp_path):
    corpus_path = tmp_path / "property-corpus.json"
    decisions_path = tmp_path / "containment-decisions.json"
    assert producer.main([
        "--candidate-identity-digest", _CANDIDATE,
        "--property-corpus-output", str(corpus_path),
        "--containment-decisions-output", str(decisions_path),
    ]) == 0
    assert corpus_path.read_bytes() == path_identity.canonical_property_corpus_bytes()
    assert path_identity.read_containment_decisions(
        decisions_path.read_bytes(),
        candidate_identity_digest=_CANDIDATE,
        input_bodies=_inputs(),
    )["case_count"] == 96


def test_release_scope_binds_every_path_identity_source_and_schema():
    assert set(path_identity.INPUT_PATHS.items()) <= set(contracts.SCOPE_INPUT_PATHS.items())
    assert contracts.SCHEMA_PATHS["path-identity-corpus-schema"] == \
        path_identity.INPUT_PATHS["path-identity-corpus-schema"]
    assert contracts.SCHEMA_PATHS["path-identity-decisions-schema"] == \
        path_identity.INPUT_PATHS["path-identity-decisions-schema"]
