"""Focused immutable-policy checks for B-COVERAGE evidence."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import runpy
import sys

import pytest
from jsonschema import Draft202012Validator

from quarry_recon import release_contracts as contracts
from quarry_recon import release_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.offline


def test_coverage_policy_freezes_config_tool_roster_critical_modules_and_jobs():
    policy = contracts.read_coverage_policy(
        (ROOT / contracts.COVERAGE_POLICY_PATH).read_bytes()
    )
    assert policy["critical_modules"] == list(contracts._COVERAGE_CRITICAL_MODULES)
    assert policy["h0_job_ids"] == list(contracts._COVERAGE_H0_JOB_IDS)
    assert policy["config"]["digest"] == contracts.raw_sha256(
        (ROOT / ".coveragerc").read_bytes()
    )
    assert policy["source_roster"] == sorted(
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "src/quarry_recon").rglob("*.py")
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda policy: policy.update(version="0.0.0"),
        lambda policy: policy["critical_modules"].pop(),
        lambda policy: policy["h0_job_ids"].reverse(),
        lambda policy: policy["source_roster"].reverse(),
        lambda policy: policy["config"].update(path="other"),
    ],
)
def test_coverage_policy_refuses_drift(mutate):
    policy = contracts.read_coverage_policy(
        (ROOT / contracts.COVERAGE_POLICY_PATH).read_bytes()
    )
    with pytest.raises(evidence.EvidenceError):
        contracts.validate_coverage_policy(mutate_and_return(policy, mutate))


def test_coverage_shard_producer_emits_schema_checked_canonical_fragment(
    tmp_path, monkeypatch
):
    policy_path = ROOT / contracts.COVERAGE_POLICY_PATH
    policy = contracts.read_coverage_policy(policy_path.read_bytes())
    coverage_json = {
        "meta": {
            "branch_coverage": True,
            "format": 3,
            "show_contexts": True,
            "version": "7.15.4",
        },
        "files": {
            path: {
                "executed_branches": [[1, 2]],
                "executed_lines": [1, 2],
                "contexts": {
                    "1": [policy["h0_job_ids"][0]],
                    "2": [policy["h0_job_ids"][0]],
                },
                "missing_branches": [],
                "missing_lines": [],
                "summary": {
                    "covered_branches": 1,
                    "covered_lines": 2,
                    "num_branches": 1,
                    "num_statements": 2,
                },
            }
            for path in policy["source_roster"]
        },
    }
    coverage_path = tmp_path / "coverage.json"
    data_path = tmp_path / "coverage-data"
    h0_path = tmp_path / "h0.json"
    output_path = tmp_path / "coverage-shard.json"
    coverage_path.write_text(json.dumps(coverage_json))
    data_path.write_bytes(b"coverage-data")
    h0_path.write_bytes(b"h0-fragment")
    arguments = [
        str(ROOT / "scripts/emit_coverage_shard.py"),
        "--coverage-json",
        str(coverage_path),
        "--coverage-data",
        str(data_path),
        "--config",
        str(ROOT / ".coveragerc"),
        "--h0-fragment",
        str(h0_path),
        "--job-instance-id",
        policy["h0_job_ids"][0],
        "--policy",
        str(policy_path),
        "--output",
        str(output_path),
    ]
    monkeypatch.setattr(sys, "argv", arguments)
    runpy.run_path(arguments[0], run_name="__main__")
    shard_body = output_path.read_bytes()
    shard = contracts.read_coverage_shard(shard_body)
    shard_schema = json.loads(
        (ROOT / contracts.SCHEMA_PATHS["coverage-shard-schema"]).read_text()
    )
    assert list(Draft202012Validator(shard_schema).iter_errors(shard)) == []
    assert shard["source_roster"] == policy["source_roster"]
    assert shard_body == contracts.canonical_json_line(shard)
    coverage_json["meta"]["branch_coverage"] = False
    coverage_path.write_text(json.dumps(coverage_json))
    with pytest.raises(SystemExit, match="frozen branch-coverage format"):
        runpy.run_path(arguments[0], run_name="__main__")


def mutate_and_return(policy: dict, mutate) -> dict:
    changed = copy.deepcopy(policy)
    mutate(changed)
    return changed
