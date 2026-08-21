"""Focused source-contract checks for C-OUTPUT-CONTRACT; no H1 tool execution."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from quarry_recon import output_contract as contract
from quarry_recon import runner


pytestmark = pytest.mark.offline
ROOT = Path(__file__).parents[1]
DIGEST = "sha256:" + "a" * 64


def _manifest() -> dict:
    return json.loads((ROOT / "release/evidence/c-output-fixture-manifest-v1.json").read_bytes())


def _receipt(case_id: str, fixture_digest: str) -> dict:
    status = contract.EXPECTED_STATUS[case_id]
    return {
        "schema_version": contract.RAW_RECEIPT_SCHEMA,
        "case_id": case_id,
        "fixture_manifest_digest": fixture_digest,
        "tool": {"name": "gitleaks", "argv0_sha256": DIGEST, "version": "v8.30.1"},
        "result": {"status": status, "exit_code": 0 if status in {"empty", "success", "partial"} else 1, "duration_ms": 1},
        "execution": {
            "request_id": "0" * 32, "terminal": "complete", "process_group_settled": True,
            "process_tree_settled": True, "repository_publication": "published",
            "repository_ownership_settled": True,
        },
        "streams": [
            {"role": "stdout", "terminal": "complete", "observed_bytes": 0,
             "retained_bytes": 0, "observed_sha256": DIGEST, "retained_sha256": DIGEST,
             "lines": 0},
            {"role": "stderr", "terminal": "complete", "observed_bytes": 0,
             "retained_bytes": 0, "observed_sha256": DIGEST, "retained_sha256": DIGEST,
             "lines": 0},
        ],
        "native_outputs": {"clean": True, "policy_count": 0, "committed": [], "uncertain": [],
                           "unpublished": [], "cleanup_settled": True, "claim_retained": False},
        "parser": {"parser": "gitleaks-json", "outcome": (
            case_id if case_id in {"empty", "non_empty", "malformed", "truncated", "non_utf8", "partial"}
            else "unavailable"
        ),
                   "complete": case_id not in {"malformed", "truncated", "non_utf8", "partial", "timeout"}},
    }


def test_frozen_fixture_manifest_is_exactly_the_nine_required_cases():
    assert contract.validate_fixture_manifest(_manifest())["cases"][-1]["id"] == "tool_specific_exit"


def test_collects_only_a_complete_ordered_runner_receipt_matrix():
    manifest = _manifest()
    digest = "sha256:" + __import__("hashlib").sha256(contract.evidence.canonical_json_bytes(manifest)).hexdigest()
    matrix = contract.collect_case_matrix(
        fixture_manifest=manifest,
        receipts=[_receipt(case, digest) for case in contract.CASES],
    )
    assert contract.validate_case_matrix(matrix) == matrix
    assert [row["runner_status"] for row in matrix["cases"]] == [
        contract.EXPECTED_STATUS[case] for case in contract.CASES
    ]
    assert matrix["observation"] == "h1-attestation-required"


def test_rejects_unsettled_or_misclassified_raw_evidence():
    manifest = _manifest()
    digest = "sha256:" + __import__("hashlib").sha256(contract.evidence.canonical_json_bytes(manifest)).hexdigest()
    receipts = [_receipt(case, digest) for case in contract.CASES]
    receipts[0]["execution"]["process_tree_settled"] = False
    with pytest.raises(contract.OutputContractError, match="settled"):
        contract.collect_case_matrix(fixture_manifest=manifest, receipts=receipts)
    receipts = [_receipt(case, digest) for case in contract.CASES]
    receipts[1]["result"]["status"] = "empty"
    with pytest.raises(contract.OutputContractError, match="documented runner result"):
        contract.collect_case_matrix(fixture_manifest=manifest, receipts=receipts)


def test_canonical_producer_refuses_legacy_or_unsettled_runner_results():
    result = runner.RunResult(
        tool="gitleaks", cmd=["gitleaks", "version"], status=runner.Status.SUCCESS,
        exit_code=0, duration=0, raw_path=None, stdout_lines=0,
    )
    with pytest.raises(contract.OutputContractError, match="non-repository-backed"):
        contract.receipt_from_run_result(
            case_id="empty", fixture_manifest_digest=DIGEST, tool_version="v8.30.1",
            result=result, parser={"parser": "gitleaks-json", "outcome": "empty", "complete": True},
        )


def test_json_schemas_accept_canonical_source_shapes():
    Draft202012Validator = pytest.importorskip("jsonschema").Draft202012Validator
    manifest = _manifest()
    digest = "sha256:" + __import__("hashlib").sha256(contract.evidence.canonical_json_bytes(manifest)).hexdigest()
    receipt = _receipt("empty", digest)
    matrix = contract.collect_case_matrix(
        fixture_manifest=manifest,
        receipts=[_receipt(case, digest) for case in contract.CASES],
    )
    for path, document in (
        ("c-output-fixture-manifest-v1.schema.json", manifest),
        ("c-output-raw-receipt-v1.schema.json", receipt),
        ("c-output-case-matrix-v1.schema.json", matrix),
    ):
        schema = json.loads((ROOT / "release/evidence/schemas" / path).read_bytes())
        Draft202012Validator.check_schema(schema)
        assert list(Draft202012Validator(schema).iter_errors(document)) == []
