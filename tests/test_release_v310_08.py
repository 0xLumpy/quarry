from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from quarry_recon import release_v310_08


pytestmark = pytest.mark.offline

_CANDIDATE = "sha256:" + "a" * 64
_FIXTURE = "sha256:" + "b" * 64
_MANIFEST = "sha256:" + "c" * 64
_REPORT = "sha256:" + "d" * 64


def _measurement(*, digest: str = _REPORT, input_count: int = 24068, included: int = 24068,
                 artifact_bytes: int = 13_400_000, wall_ms: int = 1900,
                 rss_bytes: int = 112_000_000) -> dict:
    return {
        "trial_id": "",
        "report_digest": digest,
        "input_observations": input_count,
        "included_observations": included,
        "omitted_observations": input_count - included,
        "artifact_bytes": artifact_bytes,
        "wall_time_ms": wall_ms,
        "peak_aggregate_rss_bytes": rss_bytes,
        "artifact_differences": 0,
        "observation_coverage_basis_points": (
            10000 if input_count == 0 else included * 10000 // input_count
        ),
    }


def _report(*trials: dict) -> dict:
    if not trials:
        trials = (_measurement(), _measurement(wall_ms=2000, rss_bytes=114_000_000))
    prepared = []
    first = trials[0]["report_digest"]
    for index, value in enumerate(trials, 1):
        trial = copy.deepcopy(value)
        trial["trial_id"] = f"trial-{index:04d}"
        trial["artifact_differences"] = int(trial["report_digest"] != first)
        prepared.append(trial)
    report = {
        "schema_version": release_v310_08.SCHEMA_VERSION,
        "candidate_identity_digest": _CANDIDATE,
        "evidence_instance_id": "instance-00",
        "gate_id": "C-PERF-REPORT",
        "artifact_kind": "report-truth-measurement",
        "fixture_digest": _FIXTURE,
        "source_manifest_digest": _MANIFEST,
        "source_revision_digest": None,
        "started_at": "2026-08-15T10:00:00Z",
        "finished_at": "2026-08-15T10:00:03Z",
        "trials": prepared,
        "summary": {},
        "disposition": "descriptive_only",
        "open_reasons": ["benchmark_manifest_unreviewed", "thresholds_unreviewed"],
    }
    report["summary"] = release_v310_08._expected_summary(prepared)
    return report


def test_candidate_bound_descriptive_measurements_recompute_every_statistic():
    report = _report()
    assert release_v310_08.verify_measurement_report(
        report,
        candidate_identity_digest=_CANDIDATE,
        evidence_instance_id="instance-00",
    ) is report
    assert report["summary"] == {
        "repetitions": 2,
        "report_digest": _REPORT,
        "peak_aggregate_rss_p95_bytes": 114_000_000,
        "artifact_size_max_bytes": 13_400_000,
        "wall_time_p95_ms": 2000,
        "artifact_differences_max": 0,
        "observation_coverage_min_basis_points": 10000,
    }


def test_builder_derives_ids_coverage_and_differences_from_raw_trials():
    raw = _measurement()
    for field in ("trial_id", "artifact_differences", "observation_coverage_basis_points"):
        raw.pop(field)
    changed = copy.deepcopy(raw)
    changed["report_digest"] = "sha256:" + "e" * 64
    document = release_v310_08.build_measurement_report(
        candidate_identity_digest=_CANDIDATE,
        evidence_instance_id="instance-00",
        fixture_digest=_FIXTURE,
        source_manifest_digest=_MANIFEST,
        source_revision_digest=None,
        started_at="2026-08-15T10:00:00Z",
        finished_at="2026-08-15T10:00:03Z",
        trials=[raw, changed],
    )
    assert [trial["trial_id"] for trial in document["trials"]] == ["trial-0001", "trial-0002"]
    assert [trial["artifact_differences"] for trial in document["trials"]] == [0, 1]
    assert document["summary"]["report_digest"] is None
    assert document["summary"]["artifact_differences_max"] == 1


def test_counts_coverage_determinism_and_summary_cannot_be_forged():
    vectors = []
    bad = _report()
    bad["trials"][0]["included_observations"] -= 1
    vectors.append(bad)
    bad = _report()
    bad["trials"][1]["report_digest"] = "sha256:" + "e" * 64
    vectors.append(bad)
    bad = _report()
    bad["summary"]["wall_time_p95_ms"] -= 1
    vectors.append(bad)
    bad = _report()
    bad["trials"][1]["trial_id"] = "trial-0003"
    vectors.append(bad)
    for report in vectors:
        with pytest.raises(release_v310_08.V31008EvidenceError):
            release_v310_08.verify_measurement_report(report)


def test_measurement_contract_cannot_launder_open_thresholds_into_pass():
    report = _report()
    report["disposition"] = "pass"
    with pytest.raises(release_v310_08.V31008EvidenceError, match="cannot claim"):
        release_v310_08.verify_measurement_report(report)

    report = _report()
    report["open_reasons"] = []
    with pytest.raises(release_v310_08.V31008EvidenceError, match="cannot claim"):
        release_v310_08.verify_measurement_report(report)


def test_candidate_instance_and_time_bindings_fail_closed():
    report = _report()
    with pytest.raises(release_v310_08.V31008EvidenceError, match="another release"):
        release_v310_08.verify_measurement_report(
            report, candidate_identity_digest="sha256:" + "f" * 64,
        )
    with pytest.raises(release_v310_08.V31008EvidenceError, match="another evidence"):
        release_v310_08.verify_measurement_report(report, evidence_instance_id="instance-01")
    report["finished_at"] = "2026-08-15T09:59:59Z"
    with pytest.raises(release_v310_08.V31008EvidenceError, match="before"):
        release_v310_08.verify_measurement_report(report)


def test_reader_requires_canonical_single_line_without_duplicate_members():
    report = _report()
    body = release_v310_08.canonical_json_bytes(report)
    assert release_v310_08.read_measurement_report(body) == report
    with pytest.raises(release_v310_08.V31008EvidenceError, match="canonical"):
        release_v310_08.read_measurement_report(json.dumps(report).encode() + b"\n")
    duplicate = body.replace(
        b'{"artifact_kind":',
        b'{"artifact_kind":"report-truth-measurement","artifact_kind":', 1,
    )
    with pytest.raises(release_v310_08.V31008EvidenceError, match="duplicate"):
        release_v310_08.read_measurement_report(duplicate)


def test_portable_schema_matches_the_runtime_contract():
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = (Path(__file__).resolve().parents[1] / "release" / "evidence" / "schemas"
                   / "v310-report-truth-report-v1.schema.json")
    schema = json.loads(schema_path.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    checker = jsonschema.FormatChecker()
    if "date-time" not in checker.checkers:
        @checker.checks("date-time")
        def real_datetime(value):
            try:
                release_v310_08._timestamp(value, "schema timestamp")
                return True
            except release_v310_08.V31008EvidenceError:
                return False
    validator = jsonschema.Draft202012Validator(schema, format_checker=checker)
    report = _report()
    validator.validate(report)

    mutations = []
    value = _report()
    value["disposition"] = "pass"
    mutations.append(value)
    value = _report()
    value["evidence_instance_id"] = "wrong"
    mutations.append(value)
    value = _report()
    value["trials"][0]["artifact_differences"] = 2
    mutations.append(value)
    value = _report()
    value["started_at"] = "2026-02-31T00:00:00Z"
    mutations.append(value)
    value = _report()
    value["started_at"] = "0000-01-01T00:00:00Z"
    mutations.append(value)
    for value in mutations:
        assert not validator.is_valid(value)
        with pytest.raises(release_v310_08.V31008EvidenceError):
            release_v310_08.verify_measurement_report(value)
