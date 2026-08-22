"""Focused refusal cases for the frozen B-QUALITY semantic evidence."""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from quarry_recon import release_contracts as contracts
from quarry_recon import release_evidence as evidence


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.offline


def _digest(char: str) -> str:
    return f"sha256:{char * 64}"


def _selection() -> dict[str, int]:
    return {
        "collected": 6,
        "deselected": 0,
        "failed": 0,
        "passed": 6,
        "selected": 6,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
    }


def _context() -> tuple[dict, dict[str, bytes], dict]:
    policy_body = (ROOT / contracts.QUALITY_POLICY_PATH).read_bytes()
    policy = contracts.read_quality_policy(policy_body)
    raw_inputs = {
        "docs-parity-tests": (ROOT / "tests/test_docs_parity.py").read_bytes(),
        "package-metadata": (ROOT / "pyproject.toml").read_bytes(),
        "quality-policy": policy_body,
        "verification-job-map": (
            ROOT / "release/evidence/verification-job-map-v1.json"
        ).read_bytes(),
        "verification-workflow-ci": (
            ROOT / "release/evidence/dormant-ci-workflow-v1.yml"
        ).read_bytes(),
    }
    scope = {
        "input_bindings": [
            {
                "digest": contracts.raw_sha256(raw_inputs[name]),
                "name": name,
                "path": path,
            }
            for name, path in (
                ("docs-parity-tests", "tests/test_docs_parity.py"),
                ("package-metadata", "pyproject.toml"),
                ("quality-policy", contracts.QUALITY_POLICY_PATH),
                (
                    "verification-job-map",
                    "release/evidence/verification-job-map-v1.json",
                ),
                (
                    "verification-workflow-ci",
                    "release/evidence/dormant-ci-workflow-v1.yml",
                ),
            )
        ]
    }
    tools = [
        {
            "digest": _digest("1"),
            "name": "ruff",
            "path": "/tools/ruff",
            "version": "0.16.3",
        },
        {
            "digest": _digest("2"),
            "name": "mypy",
            "path": "/tools/mypy",
            "version": "2.3.1",
        },
        {
            "digest": _digest("3"),
            "name": "pytest",
            "path": "/tools/pytest",
            "version": "9.1.1",
        },
    ]
    observations = []
    for check in policy["checks"]:
        findings = (
            []
            if check["id"] in {"type", "docs"}
            else [
                ["src/quarry_recon/quality.py", "Q000", 1, 1],
            ]
        )
        encoded_findings = evidence.canonical_json_bytes(findings)
        observations.append(
            {
                "argv": check["argv"],
                "breached": False,
                "budget": check["budget"],
                "config": {
                    "digest": check["config"]["digest"],
                    "name": "quality-config",
                    "path": check["config"]["path"],
                },
                "expected_exit_code": check["expected_exit_code"],
                "exit_code": 0 if not findings else check["expected_exit_code"],
                "id": check["id"],
                "observed_count": len(findings),
                "output": "base64:"
                + base64.b64encode(encoded_findings).decode("ascii"),
                "output_kind": "canonical-findings",
                "result_digest": contracts.raw_sha256(encoded_findings),
                "sources": check["sources"],
                "tool": check["tool"],
                "version": check["version"],
            }
        )
    identity = {"candidate": "quality"}
    instance = {
        "id": "h0-quality",
        "lane": "H0-hermetic",
        "environment": {
            "architecture": "x86_64",
            "isolation_profile": _digest("5"),
            "os": "linux",
            "python": "3.12",
            "runner_image": _digest("6"),
        },
        "started_at": "2026-08-01T00:00:00Z",
        "finished_at": "2026-08-01T00:00:01Z",
        "selection": _selection(),
        "toolchain": tools,
    }
    report = {"instances": [instance]}
    document = {
        "artifact_type": "quality-report",
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": "B-QUALITY",
        "name": "quality-report",
        "release": "0.3.10",
        "schema_version": contracts.GATE_ARTIFACT_SCHEMA,
        "environment": instance["environment"],
        "evidence_instance_id": instance["id"],
        "evidence_started_at": instance["started_at"],
        "evidence_finished_at": instance["finished_at"],
        "toolchain": tools,
        "bindings": copy.deepcopy(scope["input_bindings"]),
        "quality_policy_digest": contracts.raw_sha256(policy_body),
        "threshold_manifest_digest": None,
        "quality_violations": 0,
        "observations": observations,
        "selection": _selection(),
    }
    thresholds = {
        "thresholds": [
            {
                "baseline_digest": None,
                "class": "absolute",
                "gate_id": "B-QUALITY",
                "limit": 0,
                "metric": "quality_violations",
                "operator": "at_most",
                "statistic": "maximum",
                "unit": "count",
            }
        ]
    }
    document["threshold_manifest_digest"] = contracts.raw_sha256(
        contracts.canonical_json_line(thresholds)
    )
    body = contracts.canonical_json_line(document)
    gate = {
        "gate_id": "B-QUALITY",
        "artifacts": [
            {
                "name": "quality-report",
                "media_type": "application/json",
                "digest": contracts.raw_sha256(body),
            }
        ],
        "selection": _selection(),
    }
    return (
        gate,
        {"quality-report": body},
        {
            "identity": identity,
            "report": report,
            "scope": scope,
            "thresholds": thresholds,
            "input_bodies": raw_inputs,
        },
    )


def _semantic(gate: dict, bodies: dict[str, bytes], context: dict) -> None:
    contracts._semantic_quality(gate, bodies, **context)


def test_quality_semantic_accepts_one_complete_canonical_report():
    gate, bodies, context = _context()
    _semantic(gate, bodies, context)
    schema = json.loads(
        (ROOT / contracts.SCHEMA_PATHS["gate-artifact-schema"]).read_text()
    )
    artifact = evidence.load_json_bytes(bodies["quality-report"][:-1])
    assert list(Draft202012Validator(schema).iter_errors(artifact)) == []


def test_quality_policy_schema_and_reader_freeze_exact_order():
    policy = contracts.read_quality_policy(
        (ROOT / contracts.QUALITY_POLICY_PATH).read_bytes()
    )
    assert [check["id"] for check in policy["checks"]] == list(
        contracts._QUALITY_CHECK_IDS
    )
    swapped = copy.deepcopy(policy)
    swapped["checks"][0], swapped["checks"][1] = (
        swapped["checks"][1],
        swapped["checks"][0],
    )
    with pytest.raises(evidence.EvidenceError, match="not frozen"):
        contracts.validate_quality_policy(swapped)


@pytest.mark.parametrize(
    "forgery",
    [
        lambda doc, _ctx: doc["observations"][0].update(observed_count=2),
        lambda doc, _ctx: doc["observations"][0].update(exit_code=0),
        lambda doc, _ctx: doc["observations"].reverse(),
        lambda doc, _ctx: doc["observations"][0].update(tool="mypy"),
        lambda doc, _ctx: doc["observations"][0]["argv"].append("--forged"),
        lambda doc, _ctx: doc["observations"][0].update(version="0.0.0"),
        lambda doc, _ctx: doc["observations"][0]["config"].update(path="other.toml"),
        lambda doc, _ctx: doc["observations"][0].update(sources=["other"]),
        lambda doc, _ctx: doc.update(quality_policy_digest=_digest("9")),
        lambda doc, _ctx: doc.update(threshold_manifest_digest=_digest("9")),
        lambda doc, _ctx: doc.update(evidence_instance_id="other-h0"),
        lambda doc, _ctx: doc.update(candidate_identity_digest=_digest("9")),
        lambda doc, _ctx: doc["observations"][0].pop("budget"),
    ],
)
def test_quality_semantic_refuses_forged_report(forgery):
    gate, bodies, context = _context()
    document = evidence.load_json_bytes(bodies["quality-report"][:-1])
    forgery(document, context)
    bodies["quality-report"] = contracts.canonical_json_line(document)
    gate["artifacts"][0]["digest"] = contracts.raw_sha256(bodies["quality-report"])
    with pytest.raises(evidence.EvidenceError):
        _semantic(gate, bodies, context)
