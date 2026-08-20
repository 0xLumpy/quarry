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


def _broker_record(sequence: int, syscall: str, peer: str, decision: str, *,
                   result=None, stage="settled") -> dict:
    return {
        "decision": decision,
        "peer": peer,
        "port": 8080 if peer.startswith("10.203") else 80,
        "protocol": 6 if syscall == "connect" else 17,
        "reason": "fixed boundary witness",
        "result": result,
        "sequence": sequence,
        "socket_type": 1 if syscall == "connect" else 2,
        "stage": stage,
        "syscall": syscall,
        "tid": 100,
    }


def _diagnostic() -> dict:
    broker_records = [
        _broker_record(0, "connect", "10.203.0.1", "allow", result="ok"),
        _broker_record(1, "connect", "8.8.4.4", "deny"),
        _broker_record(2, "connect", "10.203.0.2", "deny"),
        _broker_record(3, "connect", "169.254.169.254", "deny"),
        _broker_record(4, "connect", "10.203.0.99", "deny"),
        _broker_record(5, "sendto", "10.203.0.1", "allow", result="1"),
        _broker_record(6, "sendto", "169.254.169.254", "deny"),
        _broker_record(7, "sendmsg", "10.203.0.1", "allow", result="1"),
        _broker_record(8, "sendmsg", "10.203.0.99", "deny"),
    ]
    denied_hosts = (
        "bücher.fixture.test", "oos.fixture.test", "8.8.4.4",
        "mixed.fixture.test", "protected.fixture.test", "rebind.fixture.test",
    )
    proxy_records = [{
        "decision": "deny",
        "host": host,
        "method": "GET",
        "peer": None,
        "port": 8080,
        "reason": "fixed boundary refusal",
        "sequence": index,
        "stage": "authority",
    } for index, host in enumerate(denied_hosts)]
    dns_names = (
        "fixture.test", "redirect.fixture.test", "xn--bcher-kva.fixture.test",
        "mixed.fixture.test", "protected.fixture.test", "rebind.fixture.test",
    )
    return {
        "acceptance_errors": [],
        "broker": {
            "active_operations": 0,
            "complete": True,
            "dropped_records": 0,
            "fatal": None,
            "listener_hup": True,
            "open_plans": 0,
            "profile": "standard",
            "records": broker_records,
            "request_id": "a" * 32,
            "retained_connections": 0,
            "schema_version": "quarry.network-broker-summary.v1",
        },
        "dns_records": [{
            "count": 2 if name == "rebind.fixture.test" else 1,
            "dns": name,
            "kind": 1,
        } for name in dns_names],
        "http_records": [
            {"host": host, "path": path}
            for host, path in sorted(contracts._NETWORK_BOUNDARY_HTTP_CONTACTS)
        ],
        "proxy": {
            "active_sockets": 0,
            "active_threads": 0,
            "complete": True,
            "dropped_records": 0,
            "fatal": None,
            "open_plans": 0,
            "records": proxy_records,
            "request_id": "a" * 32,
            "schema_version": "quarry.browser-proxy-summary.v1",
        },
        "proxy_effects": {
            "cidr_status": 404,
            "idna_status": 404,
            "rebind_first_status": 404,
            "redirect_status": 200,
            "start_location": "http://redirect.fixture.test:8080/final",
            "start_status": 302,
        },
        "reaped": [],
        "refused": {
            "direct_ip": True,
            "mixed": True,
            "protected": True,
            "rebind": True,
            "scope": True,
            "unicode_idna": True,
        },
        "schema_version": "quarry.network-boundary-h1.v1",
        "tracee_results": {
            "approved": 0,
            "control_plane": 1,
            "direct_ip": 1,
            "metadata": 1,
            "scanner_self": 1,
            "sendmsg_allowed": 1,
            "sendmsg_control": 1,
            "sendto_allowed": 1,
            "sendto_metadata": 1,
        },
    }


def _fixture() -> tuple[dict, dict, dict]:
    identity = {"candidate": "fixture"}
    environment = {
        "architecture": "x86_64",
        "isolation_profile": _digest("b"),
        "lane": "H1-tool-integration",
        "os": "linux",
        "python": "3.12.13",
        "runner_image": _digest("a"),
    }
    support = {"environments": [environment]}
    report = {
        "candidate_identity_digest": evidence.canonical_digest(identity),
        "gate_id": "C-NETWORK-BOUNDARY",
        "instances": [{
            "diagnostic": _diagnostic(),
            "environment": {key: environment[key] for key in environment if key != "lane"},
            "identity": {
                "lane": environment["lane"],
                "python": environment["python"],
                "runner_image": environment["runner_image"],
            },
        }],
        "release": "0.3.10",
        "schema_version": contracts.NETWORK_BOUNDARY_TRACE_SCHEMA,
    }
    return identity, support, report


def _validate(identity: dict, support: dict, report: dict) -> dict:
    return contracts._validate_network_boundary_trace(
        contracts.canonical_json_line(report), identity=identity, support=support,
    )


def test_network_boundary_schema_and_semantics_accept_the_complete_h1_witness():
    identity, support, report = _fixture()
    schema = json.loads(
        (ROOT / contracts.SCHEMA_PATHS["network-boundary-trace-schema"]).read_text()
    )
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema_version"]["const"] == \
        contracts.NETWORK_BOUNDARY_TRACE_SCHEMA
    assert _validate(identity, support, report) == report
    assert contracts.SEMANTIC_VERIFIERS["C-NETWORK-BOUNDARY"] is \
        contracts._semantic_network_boundary
    assert contracts.required_artifact_contract("C-NETWORK-BOUNDARY") == (
        ("network-boundary-trace", "application/json"),
    )


@pytest.mark.parametrize("mutate", [
    lambda report: report.update({"candidate_identity_digest": _digest("9")}),
    lambda report: report["instances"][0]["diagnostic"]["acceptance_errors"].append("fault"),
    lambda report: report["instances"][0]["diagnostic"]["broker"].update({"complete": False}),
    lambda report: report["instances"][0]["diagnostic"]["proxy"].update({"open_plans": 1}),
    lambda report: report["instances"][0]["diagnostic"]["refused"].update({"rebind": False}),
    lambda report: report["instances"][0]["diagnostic"]["tracee_results"].update({"metadata": 0}),
    lambda report: report["instances"][0]["diagnostic"]["http_records"].pop(),
    lambda report: report["instances"][0]["diagnostic"]["dns_records"].pop(),
    lambda report: report["instances"][0]["diagnostic"]["proxy_effects"].update({"start_status": 200}),
    lambda report: report["instances"][0]["diagnostic"]["tracee_results"].update({"metadata": True}),
    lambda report: report["instances"][0]["diagnostic"]["broker"].update({"open_plans": False}),
])
def test_network_boundary_trace_rejects_substituted_or_incomplete_predicates(mutate):
    identity, support, report = _fixture()
    mutate(report)
    with pytest.raises(evidence.EvidenceError):
        _validate(identity, support, report)


def test_network_boundary_trace_requires_exact_resolved_h1_support_identity():
    identity, support, report = _fixture()
    support["environments"][0]["runner_image"] = _digest("c")
    with pytest.raises(evidence.EvidenceError, match="exact supported H1"):
        _validate(identity, support, report)


def test_network_boundary_trace_refuses_current_unresolved_h1_support_identity():
    identity, _support, report = _fixture()
    current = contracts.read_support_matrix(
        (ROOT / "release/evidence/support-matrix-v1.json").read_bytes(),
    )
    with pytest.raises(
        evidence.EvidenceError,
        match="support matrix H1 environment .*(isolation_profile|runner_image)",
    ):
        _validate(identity, current, report)
