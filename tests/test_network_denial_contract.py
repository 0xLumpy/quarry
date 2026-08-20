from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from quarry_recon import release_contracts as contracts
from quarry_recon import release_evidence as evidence


pytestmark = pytest.mark.offline

ROOT = Path(__file__).resolve().parents[1]


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def _environment(lane: str, image: str, python: str) -> dict:
    return {
        "architecture": "x86_64",
        "isolation_profile": _digest("f"),
        "lane": lane,
        "os": "linux",
        "python": python,
        "runner_image": _digest(image),
    }


def _attempts() -> list[dict]:
    return [{
        "denial": {"code": "ENETUNREACH", "detail": "network denied"},
        "elapsed_milliseconds": 1,
        "kind": kind,
        "outcome": "denied",
    } for kind in ("native-tool", "proxy", "resolver", "socket", "subprocess")]


def _fixture() -> tuple[dict, dict, dict]:
    identity = {"candidate": "fixture"}
    support = {"environments": [
        _environment("H0-hermetic", "a", "3.10.20"),
        _environment("C0-private-corpus", "b", "3.12.13"),
        _environment("P0-package-supply", "c", "3.12.13"),
    ]}
    instances = []
    for environment in support["environments"]:
        instances.append({
            "attempts": _attempts(),
            "environment": {key: environment[key] for key in environment if key != "lane"},
            "identity": {
                "lane": environment["lane"],
                "python": environment["python"],
                "runner_image": environment["runner_image"],
            },
        })
    report = {
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": "C-NET-DENY",
        "instances": instances,
        "release": "0.3.10",
        "schema_version": contracts.NETWORK_DENIAL_REPORT_SCHEMA,
    }
    return identity, support, report


def _validate(identity: dict, support: dict, report: dict) -> dict:
    return contracts._validate_network_denial_report(
        contracts.canonical_json_line(report), identity=identity, support=support,
    )


def test_network_denial_schema_and_semantic_verifier_accept_the_complete_golden_matrix():
    identity, support, report = _fixture()
    schema = json.loads((ROOT / contracts.SCHEMA_PATHS["network-denial-report-schema"]).read_text())
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema_version"]["const"] == contracts.NETWORK_DENIAL_REPORT_SCHEMA
    assert schema["$defs"]["instance"]["properties"]["attempts"]["maxItems"] == 5

    assert _validate(identity, support, report) == report
    assert contracts.SEMANTIC_VERIFIERS["C-NET-DENY"] is contracts._semantic_network_denial
    assert contracts.required_artifact_contract("C-NET-DENY") == (
        ("network-denial-report", "application/json"),
    )


@pytest.mark.parametrize("mutate", [
    lambda report: report["instances"][0].update({"attempts": _attempts()[:-1]}),
    lambda report: report["instances"].append(copy.deepcopy(report["instances"][0])),
    lambda report: report["instances"][1]["attempts"][3].update({"outcome": "allowed"}),
    lambda report: report["instances"][1]["attempts"][2].update({"elapsed_milliseconds": True}),
    lambda report: report["instances"][2]["attempts"][4].update({"elapsed_milliseconds": 60_001}),
    lambda report: report["instances"][2]["identity"].update({"runner_image": "not-a-digest"}),
    lambda report: report["instances"][2]["attempts"][0].update({"kind": "socket"}),
])
def test_network_denial_report_rejects_incomplete_duplicate_or_non_denied_cases(mutate):
    identity, support, report = _fixture()
    mutate(report)
    with pytest.raises(evidence.EvidenceError):
        _validate(identity, support, report)


def test_network_denial_report_requires_every_fixed_lane_even_when_c0_is_otherwise_unselected():
    identity, support, report = _fixture()
    report["instances"] = [
        instance for instance in report["instances"]
        if instance["identity"]["lane"] != "C0-private-corpus"
    ]
    with pytest.raises(evidence.EvidenceError, match="instance count|exact supported"):
        _validate(identity, support, report)


def test_network_denial_report_refuses_a_support_matrix_without_the_c0_lane():
    identity, support, report = _fixture()
    support["environments"] = [
        environment for environment in support["environments"]
        if environment["lane"] != "C0-private-corpus"
    ]

    with pytest.raises(evidence.EvidenceError, match="omits a required network denial lane"):
        _validate(identity, support, report)


def test_network_denial_report_rejects_current_unresolved_support_identities_at_evidence_time():
    identity, _support, report = _fixture()
    current_support = contracts.read_support_matrix(
        (ROOT / "release/evidence/support-matrix-v1.json").read_bytes(),
    )

    with pytest.raises(evidence.EvidenceError, match="support matrix network denial environment .*isolation_profile"):
        _validate(identity, current_support, report)
