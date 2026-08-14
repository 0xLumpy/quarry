"""Obligation-specific evidence contracts for V310-05 release gates."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from quarry_recon import release_v310_05


pytestmark = pytest.mark.offline

_CANDIDATE = "sha256:" + "a" * 64
_IDENTITY = "sha256:" + "b" * 64
_ARTIFACT = "sha256:" + "c" * 64


def _report(gate_id: str, artifact_kind: str) -> dict:
    matrix = release_v310_05._MATRICES[(gate_id, artifact_kind)]
    identity_mode = (
        "switch" if (gate_id, artifact_kind) == ("C-INSTALL-ROLLBACK", "filesystem-trace")
        else "none" if gate_id == "C-SECRETS"
        else "preserve"
    )
    return {
        "schema_version": release_v310_05.SCHEMA_VERSION,
        "candidate_identity_digest": _CANDIDATE,
        "gate_id": gate_id,
        "artifact_kind": artifact_kind,
        "started_at": "2026-08-14T10:00:00Z",
        "finished_at": "2026-08-14T10:01:00Z",
        "trials": [
            {
                "case": case,
                "outcome": "pass",
                "assertions": {name: True for name in sorted(assertions)},
                "before_identity": None if identity_mode == "none" else _IDENTITY,
                "after_identity": (
                    None if identity_mode == "none"
                    else "sha256:" + "d" * 64 if identity_mode == "switch"
                    else _IDENTITY
                ),
                "artifact_digests": [_ARTIFACT],
            }
            for case, assertions in sorted(matrix.items())
        ],
        "verdict": "pass",
    }


def _body(report: dict) -> bytes:
    return (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()


@pytest.mark.parametrize("gate_id,artifact_kind", sorted(release_v310_05._MATRICES))
def test_every_v310_05_artifact_has_an_exact_accepting_parser(gate_id, artifact_kind):
    report = _report(gate_id, artifact_kind)
    assert release_v310_05.verify_gate_report(
        report,
        gate_id=gate_id,
        artifact_kind=artifact_kind,
        candidate_identity_digest=_CANDIDATE,
    ) is report


@pytest.mark.parametrize("gate_id,artifact_kinds", sorted(release_v310_05._GATE_ARTIFACTS.items()))
def test_each_gate_requires_its_complete_exact_artifact_family(gate_id, artifact_kinds):
    bodies = {kind: _body(_report(gate_id, kind)) for kind in artifact_kinds}
    parsed = release_v310_05.verify_gate_artifacts(
        gate_id, bodies, candidate_identity_digest=_CANDIDATE,
    )
    assert set(parsed) == set(artifact_kinds)
    missing = dict(bodies)
    missing.pop(artifact_kinds[0])
    with pytest.raises(release_v310_05.V31005EvidenceError, match="requires exactly"):
        release_v310_05.verify_gate_artifacts(
            gate_id, missing, candidate_identity_digest=_CANDIDATE,
        )


def test_portable_schema_is_valid_and_accepts_the_semantically_valid_shape():
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = (Path(__file__).resolve().parents[1] / "release" / "evidence" / "schemas"
                   / "v310-installer-runtime-report-v1.schema.json")
    schema = json.loads(schema_path.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(
        _report("C-INSTALL-ROLLBACK", "fault-matrix")
    )


def test_generic_green_wrapper_is_not_v310_05_evidence():
    with pytest.raises(release_v310_05.V31005EvidenceError):
        release_v310_05.verify_gate_report({
            "gate_id": "C-INSTALL-ROLLBACK", "verdict": "pass",
        })


def test_missing_or_duplicate_fault_case_cannot_be_rendered_over_by_pass():
    report = _report("C-FAULT-INSTALL", "fault-matrix")
    report["trials"].pop()
    with pytest.raises(release_v310_05.V31005EvidenceError, match="exactly cover"):
        release_v310_05.verify_gate_report(report)

    report = _report("C-FAULT-INSTALL", "fault-matrix")
    report["trials"][-1] = copy.deepcopy(report["trials"][0])
    with pytest.raises(release_v310_05.V31005EvidenceError, match="duplicate"):
        release_v310_05.verify_gate_report(report)


def test_assertion_names_and_values_are_semantically_recomputed():
    report = _report("C-SECRETS", "sink-scan")
    report["trials"][0]["assertions"]["matches_zero"] = False
    with pytest.raises(release_v310_05.V31005EvidenceError, match="changes or fails"):
        release_v310_05.verify_gate_report(report)

    report = _report("C-SECRETS", "sink-scan")
    report["trials"][0]["assertions"]["invented"] = True
    with pytest.raises(release_v310_05.V31005EvidenceError, match="changes or fails"):
        release_v310_05.verify_gate_report(report)


def test_install_and_execution_identity_must_reconcile_exactly():
    report = _report("C-EXEC-IDENTITY", "launch-trace")
    report["trials"][0]["after_identity"] = "sha256:" + "d" * 64
    with pytest.raises(release_v310_05.V31005EvidenceError, match="reconcile identity"):
        release_v310_05.verify_gate_report(report)


def test_successful_install_trace_must_prove_a_new_active_identity():
    report = _report("C-INSTALL-ROLLBACK", "filesystem-trace")
    report["trials"][0]["after_identity"] = report["trials"][0]["before_identity"]
    with pytest.raises(release_v310_05.V31005EvidenceError, match="new active identity"):
        release_v310_05.verify_gate_report(report)


def test_secret_evidence_cannot_invent_runtime_identity_fields():
    report = _report("C-SECRETS", "canary-matrix")
    report["trials"][0]["before_identity"] = _IDENTITY
    with pytest.raises(release_v310_05.V31005EvidenceError, match="cannot invent"):
        release_v310_05.verify_gate_report(report)


def test_candidate_binding_chronology_and_artifact_digests_fail_closed():
    report = _report("C-INSTALL-ROLLBACK", "filesystem-trace")
    with pytest.raises(release_v310_05.V31005EvidenceError, match="another release candidate"):
        release_v310_05.verify_gate_report(
            report, candidate_identity_digest="sha256:" + "e" * 64,
        )
    report["finished_at"] = "2026-08-14T09:59:00Z"
    with pytest.raises(release_v310_05.V31005EvidenceError, match="before"):
        release_v310_05.verify_gate_report(report)

    report = _report("C-INSTALL-ROLLBACK", "filesystem-trace")
    report["trials"][0]["artifact_digests"] *= 2
    with pytest.raises(release_v310_05.V31005EvidenceError, match="unique trace"):
        release_v310_05.verify_gate_report(report)

    report = _report("C-INSTALL-ROLLBACK", "filesystem-trace")
    report["trials"][0]["artifact_digests"] = [{}]
    with pytest.raises(release_v310_05.V31005EvidenceError, match="unique trace"):
        release_v310_05.verify_gate_report(report)


def test_reader_requires_one_canonical_json_line_and_rejects_duplicate_members():
    report = _report("C-SECRETS", "canary-matrix")
    canonical = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    assert release_v310_05.read_gate_report(canonical) == report
    with pytest.raises(release_v310_05.V31005EvidenceError, match="canonical"):
        release_v310_05.read_gate_report(json.dumps(report).encode() + b"\n")
    duplicate = canonical.replace(b'{"artifact_kind":', b'{"artifact_kind":"canary-matrix","artifact_kind":', 1)
    with pytest.raises(release_v310_05.V31005EvidenceError, match="duplicate JSON member"):
        release_v310_05.read_gate_report(duplicate)
    nonfinite = canonical.replace(b'"verdict":"pass"', b'"verdict":NaN')
    with pytest.raises(release_v310_05.V31005EvidenceError, match="non-finite"):
        release_v310_05.read_gate_report(nonfinite)


def test_schema_and_runtime_reject_the_same_structural_semantic_vectors():
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = (Path(__file__).resolve().parents[1] / "release" / "evidence" / "schemas"
                   / "v310-installer-runtime-report-v1.schema.json")
    validator = jsonschema.Draft202012Validator(json.loads(schema_path.read_text()))
    vectors = []

    wrong_pair = _report("C-SECRETS", "sink-scan")
    wrong_pair["artifact_kind"] = "launch-trace"
    vectors.append(wrong_pair)

    missing = _report("C-EXEC-IDENTITY", "receipt-reconciliation")
    missing["trials"].pop()
    vectors.append(missing)

    duplicate = _report("C-FAULT-INSTALL", "fault-matrix")
    duplicate["trials"][-1] = copy.deepcopy(duplicate["trials"][0])
    vectors.append(duplicate)

    wrong_assertions = _report("C-SECRETS", "canary-matrix")
    wrong_assertions["trials"][0]["assertions"]["invented"] = True
    vectors.append(wrong_assertions)

    failed = _report("C-INSTALL-ROLLBACK", "fault-matrix")
    failed["trials"][0]["outcome"] = "fail"
    vectors.append(failed)

    offset = _report("C-INSTALL-ROLLBACK", "fault-matrix")
    offset["started_at"] = "2026-08-14T13:00:00+03:00"
    vectors.append(offset)

    secret_identity = _report("C-SECRETS", "sink-scan")
    secret_identity["trials"][0]["before_identity"] = _IDENTITY
    vectors.append(secret_identity)

    for report in vectors:
        assert not validator.is_valid(report)
        with pytest.raises(release_v310_05.V31005EvidenceError):
            release_v310_05.verify_gate_report(report)
