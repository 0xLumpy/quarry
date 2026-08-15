"""Strict descriptive evidence for the V310-08 private-report implementation.

The reviewed v0.3.10 threshold manifest intentionally leaves C-PERF-REPORT's
benchmark parameters and numeric limits unset.  This artifact therefore records
candidate-bound measurements and recomputes their statistics, but its only
legal disposition is ``descriptive_only``.  A later release adapter must still
refuse promotion until it consumes a reviewed benchmark manifest and thresholds.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime


SCHEMA_VERSION = "quarry.v310-report-truth-report.v1"
MAX_V31008_GATE_REPORT_BYTES = 4 * 1024 * 1024
MAX_V31008_GATE_REPORT_TRIALS = 1000

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INSTANCE = re.compile(r"instance-[0-9]{2}\Z")
_TRIAL_ID = re.compile(r"trial-[0-9]{4}\Z")
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
_REPORT_KEYS = {
    "schema_version", "candidate_identity_digest", "evidence_instance_id",
    "gate_id", "artifact_kind", "fixture_digest", "source_manifest_digest",
    "source_revision_digest", "started_at", "finished_at", "trials",
    "summary", "disposition", "open_reasons",
}
_TRIAL_KEYS = {
    "trial_id", "report_digest", "input_observations", "included_observations",
    "omitted_observations", "artifact_bytes", "wall_time_ms",
    "peak_aggregate_rss_bytes", "artifact_differences",
    "observation_coverage_basis_points",
}
_RAW_TRIAL_KEYS = _TRIAL_KEYS - {
    "trial_id", "artifact_differences", "observation_coverage_basis_points",
}
_SUMMARY_KEYS = {
    "repetitions", "report_digest", "peak_aggregate_rss_p95_bytes",
    "artifact_size_max_bytes", "wall_time_p95_ms", "artifact_differences_max",
    "observation_coverage_min_basis_points",
}
_OPEN_REASONS = ["benchmark_manifest_unreviewed", "thresholds_unreviewed"]


class V31008EvidenceError(ValueError):
    """A V310-08 measurement artifact is structurally or semantically false."""


def _exact(value, keys: set[str], where: str) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise V31008EvidenceError(f"{where} does not carry its exact fields")
    return value


def _text(value, where: str) -> str:
    if type(value) is not str or not value:
        raise V31008EvidenceError(f"{where} must be an exact non-empty string")
    return value


def _digest(value, where: str, *, nullable: bool = False):
    if nullable and value is None:
        return None
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise V31008EvidenceError(f"{where} must be a canonical sha256 digest")
    return value


def _count(value, where: str, *, maximum: int = (1 << 63) - 1) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise V31008EvidenceError(f"{where} must be a portable non-negative integer")
    return value


def _timestamp(value, where: str) -> float:
    text = _text(value, where)
    if _RFC3339.fullmatch(text) is None:
        raise V31008EvidenceError(f"{where} must be canonical UTC RFC3339")
    try:
        return datetime.fromisoformat(text[:-1] + "+00:00").timestamp()
    except ValueError as exc:
        raise V31008EvidenceError(f"{where} is not a real timestamp") from exc


def _nearest_rank_p95(values: list[int]) -> int:
    ordered = sorted(values)
    return ordered[max(0, (95 * len(ordered) + 99) // 100 - 1)]


def _expected_summary(trials: list[dict]) -> dict:
    digests = {trial["report_digest"] for trial in trials}
    return {
        "repetitions": len(trials),
        "report_digest": next(iter(digests)) if len(digests) == 1 else None,
        "peak_aggregate_rss_p95_bytes": _nearest_rank_p95([
            trial["peak_aggregate_rss_bytes"] for trial in trials
        ]),
        "artifact_size_max_bytes": max(trial["artifact_bytes"] for trial in trials),
        "wall_time_p95_ms": _nearest_rank_p95([trial["wall_time_ms"] for trial in trials]),
        "artifact_differences_max": max(trial["artifact_differences"] for trial in trials),
        "observation_coverage_min_basis_points": min(
            trial["observation_coverage_basis_points"] for trial in trials
        ),
    }


def build_measurement_report(*, candidate_identity_digest: str, evidence_instance_id: str,
                             fixture_digest: str, source_manifest_digest: str,
                             source_revision_digest: str | None, started_at: str,
                             finished_at: str, trials: list[dict]) -> dict:
    """Build derived trial identities/coverage/difference statistics from raw measurements."""
    if type(trials) is not list or not 1 <= len(trials) <= MAX_V31008_GATE_REPORT_TRIALS:
        raise V31008EvidenceError("measurement report has no finite trial set")
    prepared = []
    first_digest = None
    for index, raw in enumerate(trials, 1):
        trial = _exact(raw, _RAW_TRIAL_KEYS, f"raw_trials[{index - 1}]")
        digest = _digest(trial["report_digest"], f"raw_trials[{index - 1}].report_digest")
        if first_digest is None:
            first_digest = digest
        item = dict(trial)
        item["trial_id"] = f"trial-{index:04d}"
        input_count = _count(item["input_observations"], "input_observations")
        included = _count(item["included_observations"], "included_observations")
        omitted = _count(item["omitted_observations"], "omitted_observations")
        for field in ("artifact_bytes", "wall_time_ms", "peak_aggregate_rss_bytes"):
            _count(item[field], field)
        if input_count != included + omitted:
            raise V31008EvidenceError("a raw trial's observation counts do not reconcile")
        item["artifact_differences"] = int(digest != first_digest)
        item["observation_coverage_basis_points"] = (
            10000 if input_count == 0 else included * 10000 // input_count
        )
        prepared.append(item)
    document = {
        "schema_version": SCHEMA_VERSION,
        "candidate_identity_digest": candidate_identity_digest,
        "evidence_instance_id": evidence_instance_id,
        "gate_id": "C-PERF-REPORT",
        "artifact_kind": "report-truth-measurement",
        "fixture_digest": fixture_digest,
        "source_manifest_digest": source_manifest_digest,
        "source_revision_digest": source_revision_digest,
        "started_at": started_at,
        "finished_at": finished_at,
        "trials": prepared,
        "summary": _expected_summary(prepared),
        "disposition": "descriptive_only",
        "open_reasons": list(_OPEN_REASONS),
    }
    return verify_measurement_report(document)


def verify_measurement_report(document, *, candidate_identity_digest: str | None = None,
                              evidence_instance_id: str | None = None) -> dict:
    report = _exact(document, _REPORT_KEYS, "V310-08 measurement report")
    if report["schema_version"] != SCHEMA_VERSION \
            or report["gate_id"] != "C-PERF-REPORT" \
            or report["artifact_kind"] != "report-truth-measurement":
        raise V31008EvidenceError("report does not name the V310-08 measurement contract")
    candidate = _digest(report["candidate_identity_digest"], "candidate_identity_digest")
    if candidate_identity_digest is not None and candidate != candidate_identity_digest:
        raise V31008EvidenceError("report belongs to another release candidate")
    instance = _text(report["evidence_instance_id"], "evidence_instance_id")
    if _INSTANCE.fullmatch(instance) is None:
        raise V31008EvidenceError("evidence_instance_id is not canonical")
    if evidence_instance_id is not None and instance != evidence_instance_id:
        raise V31008EvidenceError("report belongs to another evidence instance")
    _digest(report["fixture_digest"], "fixture_digest")
    _digest(report["source_manifest_digest"], "source_manifest_digest")
    _digest(report["source_revision_digest"], "source_revision_digest", nullable=True)
    if _timestamp(report["finished_at"], "finished_at") \
            < _timestamp(report["started_at"], "started_at"):
        raise V31008EvidenceError("report finishes before it starts")
    if report["disposition"] != "descriptive_only" or report["open_reasons"] != _OPEN_REASONS:
        raise V31008EvidenceError("V310-08 measurements cannot claim a release-gate pass")

    trials = report["trials"]
    if type(trials) is not list or not 1 <= len(trials) <= MAX_V31008_GATE_REPORT_TRIALS:
        raise V31008EvidenceError("measurement report has no finite trial set")
    first_digest = None
    for index, raw in enumerate(trials, 1):
        trial = _exact(raw, _TRIAL_KEYS, f"trials[{index - 1}]")
        if trial["trial_id"] != f"trial-{index:04d}" or _TRIAL_ID.fullmatch(trial["trial_id"]) is None:
            raise V31008EvidenceError("measurement trials are not a canonical complete sequence")
        digest = _digest(trial["report_digest"], f"trials[{index - 1}].report_digest")
        if first_digest is None:
            first_digest = digest
        expected_difference = 0 if digest == first_digest else 1
        for field in (
                "input_observations", "included_observations", "omitted_observations",
                "artifact_bytes", "wall_time_ms", "peak_aggregate_rss_bytes"):
            _count(trial[field], f"trials[{index - 1}].{field}")
        _count(trial["artifact_differences"], "artifact_differences", maximum=1)
        _count(
            trial["observation_coverage_basis_points"],
            "observation_coverage_basis_points", maximum=10000,
        )
        if trial["input_observations"] != (
                trial["included_observations"] + trial["omitted_observations"]):
            raise V31008EvidenceError("a trial's observation counts do not reconcile")
        coverage = (10000 if trial["input_observations"] == 0 else
                    trial["included_observations"] * 10000 // trial["input_observations"])
        if trial["observation_coverage_basis_points"] != coverage \
                or trial["artifact_differences"] != expected_difference:
            raise V31008EvidenceError("a trial's derived measurements do not reconcile")

    summary = _exact(report["summary"], _SUMMARY_KEYS, "measurement summary")
    for field in _SUMMARY_KEYS - {"report_digest"}:
        _count(summary[field], f"summary.{field}", maximum=(10000 if "basis_points" in field else
                                                             (1 << 63) - 1))
    _digest(summary["report_digest"], "summary.report_digest", nullable=True)
    if summary != _expected_summary(trials):
        raise V31008EvidenceError("measurement summary is not recomputed from every raw trial")
    return report


def canonical_json_bytes(document: dict) -> bytes:
    try:
        body = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise V31008EvidenceError("measurement report is not canonical JSON data") from exc
    if len(body) > MAX_V31008_GATE_REPORT_BYTES:
        raise V31008EvidenceError("measurement report exceeds its byte contract")
    return body


def read_measurement_report(body: bytes, **expected) -> dict:
    if type(body) is not bytes or len(body) > MAX_V31008_GATE_REPORT_BYTES \
            or not body.endswith(b"\n") or body.endswith(b"\n\n"):
        raise V31008EvidenceError("measurement report violates its byte/line contract")

    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise V31008EvidenceError(f"duplicate JSON member {key!r}")
            value[key] = item
        return value

    try:
        document = json.loads(
            body[:-1].decode("utf-8", "strict"), object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                V31008EvidenceError(f"non-finite JSON number {value!r}"),
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise V31008EvidenceError("measurement report is not strict JSON") from exc
    if canonical_json_bytes(document) != body:
        raise V31008EvidenceError("measurement report bytes are not canonical")
    return verify_measurement_report(document, **expected)


def report_digest(document: dict) -> str:
    """Digest exact canonical report bytes for an artifact index/signature."""
    return "sha256:" + hashlib.sha256(canonical_json_bytes(document)).hexdigest()
