"""Obligation-specific semantic evidence for V310-06 release gates."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from quarry_recon import resource_contract

pytestmark = pytest.mark.offline

_CANDIDATE = "sha256:" + "a" * 64
_BASELINE = "sha256:" + "b" * 64
_THRESHOLDS = "sha256:" + "d" * 64
_INSTANCE = "instance-00"


def _accepted_thresholds(gate_id: str) -> dict:
    accepted = {}
    for metric, (operator, statistic, unit) in resource_contract._GATE_METRICS[gate_id].items():
        if metric in resource_contract._ZERO_INVARIANTS:
            limit = 0
        elif operator == "at_least":
            limit = 10_000 if unit == "basis_points" else 1
        elif metric == "peak_aggregate_rss":
            limit = 2048
        else:
            limit = 2
        accepted[metric] = {
            "operator": operator,
            "statistic": statistic,
            "unit": unit,
            "limit": limit,
            "baseline_digest": _BASELINE if metric.endswith("_delta") else None,
        }
    return accepted


def _verify(report, **expected):
    accepted = expected.pop(
        "accepted_thresholds", _accepted_thresholds(report.get("gate_id", "")),
    )
    return resource_contract.verify_gate_report(
        report,
        evidence_instance_id=expected.pop("evidence_instance_id", _INSTANCE),
        threshold_manifest_digest=_THRESHOLDS,
        benchmark_manifest_digest=(
            _BASELINE if report.get("gate_id", "").startswith("C-PERF-") else None
        ),
        accepted_thresholds=accepted,
        **expected,
    )


def _report(gate_id: str) -> dict:
    support = resource_contract.support_envelope()
    accepted = _accepted_thresholds(gate_id)
    values = {
        metric: (
            0 if metric in resource_contract._ZERO_INVARIANTS
            else 10_000 if operator == "at_least" and unit == "basis_points"
            else 1 if operator == "at_least"
            else 1024 if metric == "peak_aggregate_rss"
            else 1
        )
        for metric, (operator, _statistic, unit) in resource_contract._GATE_METRICS[gate_id].items()
    }
    trials = [
        {
            "case": case,
            "outcome": "pass",
            "resource": {
                "peak_aggregate_rss_bytes": 1024,
                "peak_disk_bytes": 2048,
                "peak_fd_count": 8,
                "peak_process_count": 2,
                "complete": True,
            },
            "metric_facts": dict(values),
            "assertions": {
                name: True
                for name in sorted(resource_contract._GATE_ASSERTIONS[gate_id][case])
            },
            "artifact_digests": ["sha256:" + "c" * 64],
        }
        for case in sorted(resource_contract._GATE_CASES[gate_id])
    ]
    measurements = []
    for metric, (operator, statistic, unit) in resource_contract._GATE_METRICS[gate_id].items():
        value = values[metric]
        limit = accepted[metric]["limit"]
        measurements.append({
            "metric": metric,
            "operator": operator,
            "statistic": statistic,
            "unit": unit,
            "value": value,
            "limit": limit,
            "passed": True,
            "baseline_digest": _BASELINE if metric.endswith("_delta") else None,
        })
    return {
        "schema_version": resource_contract.SCHEMA_VERSION,
        "candidate_identity_digest": _CANDIDATE,
        "gate_id": gate_id,
        "evidence_instance_id": _INSTANCE,
        "started_at": "2026-08-14T10:00:00Z",
        "finished_at": "2026-08-14T10:01:00Z",
        "support_envelope": support,
        "support_envelope_digest": resource_contract.digest_document(support),
        "trials": trials,
        "measurements": measurements,
        "threshold_manifest_digest": _THRESHOLDS,
        "benchmark_manifest_digest": (_BASELINE if gate_id.startswith("C-PERF-") else None),
        "verdict": "pass",
    }


@pytest.mark.parametrize("gate_id", sorted(resource_contract._GATE_CASES))
def test_every_v310_06_gate_has_an_obligation_specific_accepting_parser(gate_id):
    report = _report(gate_id)
    assert _verify(
        report, gate_id=gate_id, candidate_identity_digest=_CANDIDATE,
    ) is report


def test_portable_schema_is_valid_and_accepts_the_semantically_valid_shape():
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = (Path(__file__).resolve().parents[1] / "release" / "evidence" / "schemas"
                   / "resource-gate-report-v1.schema.json")
    schema = json.loads(schema_path.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(_report("C-FAULT-DISK"))


def test_portable_schema_requires_the_canonical_evidence_instance_identity():
    schema_path = (Path(__file__).resolve().parents[1] / "release" / "evidence" / "schemas"
                   / "resource-gate-report-v1.schema.json")
    schema = json.loads(schema_path.read_text())
    assert set(schema["required"]) == set(schema["properties"])
    assert schema["properties"]["evidence_instance_id"] == {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]*$",
    }


def test_generic_green_wrapper_is_not_resource_evidence():
    with pytest.raises(resource_contract.ResourceContractError):
        resource_contract.verify_gate_report(
            {"gate_id": "C-FAULT-DISK", "verdict": "pass"},
            threshold_manifest_digest=_THRESHOLDS,
            accepted_thresholds=_accepted_thresholds("C-FAULT-DISK"),
        )


def test_missing_fault_case_cannot_be_rendered_over_by_a_pass_verdict():
    report = _report("C-FAULT-RESOLVER")
    report["trials"].pop()
    with pytest.raises(resource_contract.ResourceContractError, match="cases"):
        _verify(report)


def test_a_forged_safety_allowance_cannot_replace_the_exact_zero_invariant():
    report = _report("C-FAULT-DISK")
    metric = next(item for item in report["measurements"]
                  if item["metric"] == "destination_corruptions")
    metric["value"] = metric["limit"] = 1
    with pytest.raises(resource_contract.ResourceContractError, match="exact zero"):
        _verify(report)


def test_threshold_arithmetic_is_recomputed_not_trusted():
    report = _report("C-PERF-INGEST")
    metric = next(item for item in report["measurements"] if item["metric"] == "wall_time")
    metric["value"], metric["limit"], metric["passed"] = 3, 2, True
    with pytest.raises(resource_contract.ResourceContractError, match="trial facts"):
        _verify(report)


def test_resolver_thresholds_cannot_widen_the_bound_carried_by_the_report():
    report = _report("C-PERF-RESOLVER")
    metric = next(item for item in report["measurements"]
                  if item["metric"] == "worker_processes")
    metric["value"] = 1
    metric["limit"] = report["support_envelope"]["resolver"]["worker_processes"] + 1
    accepted = _accepted_thresholds("C-PERF-RESOLVER")
    accepted["worker_processes"]["limit"] = metric["limit"]
    with pytest.raises(resource_contract.ResourceContractError, match="published support bound"):
        _verify(report, accepted_thresholds=accepted)


def test_regression_metric_requires_the_exact_baseline_identity():
    report = _report("C-PERF-DISK")
    metric = next(item for item in report["measurements"]
                  if item["metric"] == "throughput_delta")
    metric["baseline_digest"] = None
    with pytest.raises(resource_contract.ResourceContractError, match="baseline digest"):
        _verify(report)


def test_support_envelope_bytes_and_digest_are_both_bound():
    report = _report("C-FAULT-DISK")
    report["support_envelope"] = copy.deepcopy(report["support_envelope"])
    report["support_envelope"]["store"]["overflow_payload_retained"] = True
    report["support_envelope_digest"] = resource_contract.digest_document(report["support_envelope"])
    with pytest.raises(resource_contract.ResourceContractError, match="supported v0.3.x envelope"):
        _verify(report)


def test_candidate_identity_and_chronology_are_fail_closed():
    report = _report("C-FAULT-DISK")
    with pytest.raises(resource_contract.ResourceContractError, match="another candidate"):
        _verify(
            report, candidate_identity_digest="sha256:" + "d" * 64,
        )
    report["finished_at"] = "2026-08-14T09:59:00Z"
    with pytest.raises(resource_contract.ResourceContractError, match="before"):
        _verify(report)


def test_evidence_instance_identity_is_required_and_cannot_be_relabelled():
    report = _report("C-FAULT-DISK")
    with pytest.raises(resource_contract.ResourceContractError, match="expected canonical"):
        resource_contract.verify_gate_report(
            report,
            threshold_manifest_digest=_THRESHOLDS,
            accepted_thresholds=_accepted_thresholds("C-FAULT-DISK"),
        )
    report["evidence_instance_id"] = "instance-01"
    with pytest.raises(resource_contract.ResourceContractError, match="another evidence instance"):
        _verify(report)
    report["evidence_instance_id"] = "not/a/token"
    with pytest.raises(resource_contract.ResourceContractError, match="not canonical"):
        _verify(report)


def test_expected_committed_threshold_and_benchmark_identities_are_authoritative():
    report = _report("C-PERF-DISK")
    with pytest.raises(resource_contract.ResourceContractError, match="another committed threshold"):
        resource_contract.verify_gate_report(
            report,
            evidence_instance_id=_INSTANCE,
            threshold_manifest_digest="sha256:" + "e" * 64,
            benchmark_manifest_digest=_BASELINE,
            accepted_thresholds=_accepted_thresholds("C-PERF-DISK"),
        )
    with pytest.raises(resource_contract.ResourceContractError, match="expected benchmark identity"):
        resource_contract.verify_gate_report(
            report,
            evidence_instance_id=_INSTANCE,
            threshold_manifest_digest=_THRESHOLDS,
            benchmark_manifest_digest="sha256:" + "e" * 64,
            accepted_thresholds=_accepted_thresholds("C-PERF-DISK"),
        )
    with pytest.raises(resource_contract.ResourceContractError, match="expected committed threshold"):
        resource_contract.verify_gate_report(
            report,
            evidence_instance_id=_INSTANCE,
            benchmark_manifest_digest=_BASELINE,
            accepted_thresholds=_accepted_thresholds("C-PERF-DISK"),
        )


def test_report_cannot_select_a_limit_that_contradicts_accepted_policy():
    report = _report("C-PERF-DISK")
    metric = next(item for item in report["measurements"] if item["metric"] == "fairness")
    metric["limit"] -= 1
    with pytest.raises(resource_contract.ResourceContractError, match="accepted threshold policy"):
        _verify(report)


def test_aggregate_resource_fields_are_exact_non_negative_integers():
    report = _report("C-PERF-PHASE-FAIRNESS")
    report["trials"][0]["resource"]["peak_fd_count"] = True
    with pytest.raises(resource_contract.ResourceContractError, match="non-negative"):
        _verify(report)


def test_incomplete_or_zero_aggregate_resource_samples_cannot_be_promoted():
    report = _report("C-FAULT-RESOLVER")
    report["trials"][0]["resource"]["complete"] = False
    with pytest.raises(resource_contract.ResourceContractError, match="incomplete resource"):
        _verify(report)
    report = _report("C-FAULT-RESOLVER")
    report["trials"][0]["resource"]["peak_process_count"] = 0
    with pytest.raises(resource_contract.ResourceContractError, match="resource as zero"):
        _verify(report)


def test_exact_assertion_vocabulary_and_nonempty_unique_traces_are_required():
    report = _report("C-FAULT-DISK")
    report["trials"][0]["assertions"] = {"generic_green": True}
    with pytest.raises(resource_contract.ResourceContractError, match="exact semantic"):
        _verify(report)
    report = _report("C-FAULT-DISK")
    report["trials"][0]["artifact_digests"] = []
    with pytest.raises(resource_contract.ResourceContractError, match="unique canonical"):
        _verify(report)


def test_performance_reports_bind_the_benchmark_manifest_and_fault_reports_do_not():
    report = _report("C-PERF-INGEST")
    report["benchmark_manifest_digest"] = None
    with pytest.raises(resource_contract.ResourceContractError, match="benchmark manifest"):
        _verify(report)
    report = _report("C-FAULT-DISK")
    report["benchmark_manifest_digest"] = _BASELINE
    with pytest.raises(resource_contract.ResourceContractError, match="cannot invent"):
        _verify(report)


def test_collector_recomputes_measurements_and_only_emits_a_semantic_pass():
    source = _report("C-PERF-DISK")
    measurements = copy.deepcopy(source["measurements"])
    for item in measurements:
        item.pop("passed")
    report = resource_contract.build_gate_report(
        candidate_identity_digest=_CANDIDATE,
        gate_id="C-PERF-DISK",
        evidence_instance_id=_INSTANCE,
        started_at=source["started_at"],
        finished_at=source["finished_at"],
        trials=copy.deepcopy(source["trials"]),
        measurements=measurements,
        threshold_manifest_digest=_THRESHOLDS,
        accepted_thresholds=_accepted_thresholds("C-PERF-DISK"),
        benchmark_manifest_digest=_BASELINE,
    )
    assert report["verdict"] == "pass"
    assert all(item["passed"] is True for item in report["measurements"])
    assert _verify(report) is report


def test_collector_retains_a_failed_diagnostic_without_promoting_it():
    source = _report("C-FAULT-RESOLVER")
    source["trials"][0]["outcome"] = "fail"
    source["trials"][0]["assertions"]["semantic_invariant"] = False
    report = resource_contract.build_gate_report(
        candidate_identity_digest=_CANDIDATE,
        gate_id="C-FAULT-RESOLVER",
        evidence_instance_id=_INSTANCE,
        started_at=source["started_at"],
        finished_at=source["finished_at"],
        trials=source["trials"],
        measurements=source["measurements"],
        threshold_manifest_digest=_THRESHOLDS,
        accepted_thresholds=_accepted_thresholds("C-FAULT-RESOLVER"),
    )
    assert report["verdict"] == "fail"
    with pytest.raises(resource_contract.ResourceContractError, match="did not pass"):
        _verify(report)


def test_collector_refuses_a_caller_selected_threshold_contradiction():
    source = _report("C-PERF-DISK")
    measurements = copy.deepcopy(source["measurements"])
    next(item for item in measurements if item["metric"] == "fairness")["limit"] -= 1
    report = resource_contract.build_gate_report(
        candidate_identity_digest=_CANDIDATE,
        gate_id="C-PERF-DISK",
        evidence_instance_id=_INSTANCE,
        started_at=source["started_at"],
        finished_at=source["finished_at"],
        trials=source["trials"],
        measurements=measurements,
        threshold_manifest_digest=_THRESHOLDS,
        accepted_thresholds=_accepted_thresholds("C-PERF-DISK"),
        benchmark_manifest_digest=_BASELINE,
    )
    assert report["verdict"] == "fail"
    with pytest.raises(resource_contract.ResourceContractError, match="accepted threshold policy"):
        _verify(report)


def test_report_writer_commits_exact_canonical_bytes_and_returns_their_identity(tmp_path):
    report = _report("C-FAULT-DISK")
    destination = tmp_path / "C-FAULT-DISK.json"
    digest = resource_contract.write_gate_report(destination, report)
    body = resource_contract.canonical_bytes(report)
    assert destination.read_bytes() == body
    assert digest == "sha256:" + hashlib.sha256(body).hexdigest()
    assert resource_contract.read_gate_report(
        body, gate_id="C-FAULT-DISK", candidate_identity_digest=_CANDIDATE,
        evidence_instance_id=_INSTANCE,
        threshold_manifest_digest=_THRESHOLDS,
        accepted_thresholds=_accepted_thresholds("C-FAULT-DISK"),
    ) == report


def test_report_reader_rejects_alternate_and_duplicate_json_bytes():
    report = _report("C-FAULT-DISK")
    canonical = resource_contract.canonical_bytes(report)
    with pytest.raises(resource_contract.ResourceContractError, match="canonical JSON"):
        resource_contract.read_gate_report(json.dumps(report).encode() + b"\n")
    duplicate = canonical.replace(
        b'{"benchmark_manifest_digest":',
        b'{"benchmark_manifest_digest":null,"benchmark_manifest_digest":', 1,
    )
    with pytest.raises(resource_contract.ResourceContractError, match="strict JSON"):
        resource_contract.read_gate_report(duplicate)
