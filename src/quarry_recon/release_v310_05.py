"""Strict semantic evidence contract for the four V310-05 release gates.

Generic pytest success and a literal ``"verdict":"pass"`` are not evidence for installer rollback,
credential isolation, or executed identity.  This parser requires the complete obligation-specific case
matrix, exact true assertions, candidate binding, before/after identity reconciliation, and digests for the
underlying traces.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime


SCHEMA_VERSION = "quarry.v310-installer-runtime-report.v1"

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
_REPORT_KEYS = {
    "schema_version", "candidate_identity_digest", "gate_id", "artifact_kind",
    "started_at", "finished_at", "trials", "verdict",
}
_TRIAL_KEYS = {
    "case", "outcome", "assertions", "before_identity", "after_identity",
    "artifact_digests",
}

_MATRICES = {
    ("C-INSTALL-ROLLBACK", "fault-matrix"): {
        case: {"fault_injected", "last_known_good_preserved", "partial_not_active",
               "identity_unchanged"}
        for case in (
            "download", "extract", "verify", "payload", "receipt", "privilege", "lock",
            "activation",
        )
    },
    ("C-INSTALL-ROLLBACK", "filesystem-trace"): {
        case: {"candidate_private", "receipt_complete", "pointer_atomic", "aliases_reconciled",
               "new_identity_activated"}
        for case in ("go", "pipx", "binary", "source")
    },
    ("C-FAULT-INSTALL", "fault-matrix"): {
        case: {"fault_observed", "failure_reported", "last_known_good_preserved",
               "unverified_launches_zero", "residue_settled"}
        for case in (
            "download", "extract", "verify", "payload", "receipt", "privilege", "lock",
            "activation",
        )
    },
    ("C-SECRETS", "canary-matrix"): {
        "asnmap-environment": {"declared_consumer_only", "argv_clean", "record_values_absent"},
        "subfinder-environment": {"declared_consumer_only", "argv_clean", "record_values_absent"},
        "shodan-in-process": {"child_processes_zero", "argv_clean", "record_values_absent"},
        "github-token-file": {"owner_only", "argv_clean", "cleanup_proven"},
        "nuclei-private-config": {"owner_only", "argv_clean", "cleanup_proven"},
        "dalfox-private-config": {"owner_only", "argv_clean", "cleanup_proven"},
        "interactsh-private-config": {"owner_only", "argv_clean", "cleanup_proven"},
        "unrelated-adapter": {"credential_absent", "ambient_credential_ignored"},
    },
    ("C-SECRETS", "sink-scan"): {
        case: {"synthetic_canaries_scanned", "matches_zero", "binary_safe_scan"}
        for case in (
            "argv", "process-metadata", "stdout", "stderr", "native-output", "telemetry",
            "reports", "crash-data", "runtime-receipts", "release-evidence",
            "ambient-environment",
        )
    },
    ("C-EXEC-IDENTITY", "launch-trace"): {
        "managed-go": {"absolute_anchor", "receipt_revalidated", "executed_digest_matches"},
        "managed-pipx": {"absolute_anchor", "receipt_revalidated", "executed_digest_matches"},
        "managed-binary": {"absolute_anchor", "receipt_revalidated", "executed_digest_matches"},
        "managed-source": {"absolute_anchor", "receipt_revalidated", "executed_digest_matches"},
        "distro": {"absolute_anchor", "host_digest_recorded", "executed_digest_matches"},
        "wrapper-payload": {"wrapper_bypassed", "payload_digest_matches", "interpreter_anchored"},
        "runtime-dependency": {"dependency_anchored", "dependency_digest_matches", "path_minimal"},
        "path-substitution": {"substitution_attempted", "unverified_launches_zero",
                              "anchored_identity_executed"},
    },
    ("C-EXEC-IDENTITY", "receipt-reconciliation"): {
        "executable": {"declared", "present", "digest_matches"},
        "payload": {"declared", "present", "digest_matches"},
        "template": {"declared", "present", "digest_matches"},
        "helper": {"declared", "present", "digest_matches"},
        "environment-keys": {"allowlist_exact", "credential_names_only", "values_absent"},
    },
}
_GATE_ARTIFACTS = {
    "C-INSTALL-ROLLBACK": ("fault-matrix", "filesystem-trace"),
    "C-FAULT-INSTALL": ("fault-matrix",),
    "C-SECRETS": ("canary-matrix", "sink-scan"),
    "C-EXEC-IDENTITY": ("launch-trace", "receipt-reconciliation"),
}


class V31005EvidenceError(ValueError):
    """A V310-05 report cannot support its claimed release gate."""


def _exact_object(value, keys: set[str], where: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise V31005EvidenceError(f"{where} must carry exactly {sorted(keys)}")
    return value


def _text(value, where: str) -> str:
    if type(value) is not str or not value:
        raise V31005EvidenceError(f"{where} must be an exact non-empty string")
    return value


def _digest(value, where: str, *, nullable: bool = False):
    if nullable and value is None:
        return None
    if type(value) is not str or not _DIGEST.fullmatch(value):
        raise V31005EvidenceError(f"{where} must be a canonical sha256 digest")
    return value


def _timestamp(value, where: str) -> float:
    text = _text(value, where)
    if not _RFC3339.fullmatch(text):
        raise V31005EvidenceError(f"{where} must be canonical UTC RFC3339")
    try:
        return datetime.fromisoformat(text[:-1] + "+00:00").timestamp()
    except ValueError as exc:
        raise V31005EvidenceError(f"{where} is not a real timestamp") from exc


def verify_gate_report(document, *, gate_id: str | None = None,
                       artifact_kind: str | None = None,
                       candidate_identity_digest: str | None = None) -> dict:
    """Validate one obligation artifact and return it unchanged only when it semantically passes."""
    report = _exact_object(document, _REPORT_KEYS, "V310-05 gate report")
    if report["schema_version"] != SCHEMA_VERSION:
        raise V31005EvidenceError("unknown V310-05 report schema")
    observed_gate = _text(report["gate_id"], "gate_id")
    observed_kind = _text(report["artifact_kind"], "artifact_kind")
    matrix = _MATRICES.get((observed_gate, observed_kind))
    if matrix is None:
        raise V31005EvidenceError("report does not name a V310-05 gate artifact")
    if gate_id is not None and observed_gate != gate_id:
        raise V31005EvidenceError("report belongs to another gate")
    if artifact_kind is not None and observed_kind != artifact_kind:
        raise V31005EvidenceError("report is not the required artifact kind")
    candidate = _digest(report["candidate_identity_digest"], "candidate_identity_digest")
    if candidate_identity_digest is not None and candidate != candidate_identity_digest:
        raise V31005EvidenceError("report belongs to another release candidate")
    started = _timestamp(report["started_at"], "started_at")
    finished = _timestamp(report["finished_at"], "finished_at")
    if finished < started:
        raise V31005EvidenceError("report finishes before it starts")

    trials = report["trials"]
    if not isinstance(trials, list) or not trials:
        raise V31005EvidenceError("report requires a non-empty trial matrix")
    expected_cases = sorted(matrix)
    if len(trials) != len(expected_cases):
        raise V31005EvidenceError("report does not exactly cover its obligation matrix")
    seen = set()
    identity_mode = (
        "switch" if (observed_gate, observed_kind) == ("C-INSTALL-ROLLBACK", "filesystem-trace")
        else "none" if observed_gate == "C-SECRETS"
        else "preserve"
    )
    for index, raw in enumerate(trials):
        trial = _exact_object(raw, _TRIAL_KEYS, f"trials[{index}]")
        case = _text(trial["case"], f"trials[{index}].case")
        if case in seen or case not in matrix or case != expected_cases[index]:
            raise V31005EvidenceError(f"unexpected or duplicate V310-05 case {case!r}")
        seen.add(case)
        if trial["outcome"] != "pass":
            raise V31005EvidenceError(f"V310-05 case {case!r} did not pass")
        assertions = trial["assertions"]
        if (not isinstance(assertions, dict) or set(assertions) != matrix[case]
                or any(value is not True for value in assertions.values())):
            raise V31005EvidenceError(f"V310-05 case {case!r} changes or fails its semantic assertions")
        before = _digest(trial["before_identity"], f"trials[{index}].before_identity",
                         nullable=identity_mode == "none")
        after = _digest(trial["after_identity"], f"trials[{index}].after_identity",
                        nullable=identity_mode == "none")
        if identity_mode == "preserve" and (before is None or after is None or before != after):
            raise V31005EvidenceError(f"V310-05 case {case!r} does not preserve/reconcile identity")
        if identity_mode == "switch" and (before is None or after is None or before == after):
            raise V31005EvidenceError(f"V310-05 case {case!r} does not prove a new active identity")
        if identity_mode == "none" and (before is not None or after is not None):
            raise V31005EvidenceError(f"secret case {case!r} cannot invent installation identities")
        artifacts = trial["artifact_digests"]
        if (not isinstance(artifacts, list) or not artifacts
                or any(type(value) is not str or not _DIGEST.fullmatch(value)
                       for value in artifacts)
                or len(artifacts) != len(set(artifacts))):
            raise V31005EvidenceError(f"V310-05 case {case!r} lacks unique trace digests")
    if seen != set(matrix):
        raise V31005EvidenceError("report does not exactly cover its obligation matrix")
    if report["verdict"] != "pass":
        raise V31005EvidenceError("V310-05 report verdict is not pass")
    return report


def read_gate_report(body: bytes, **expected) -> dict:
    """Read exactly one canonical JSON line, rejecting duplicates and alternate byte encodings."""
    if type(body) is not bytes or len(body) > 4 * 1024 * 1024:
        raise V31005EvidenceError("V310-05 report exceeds its byte contract")
    if not body.endswith(b"\n") or body.endswith(b"\n\n"):
        raise V31005EvidenceError("V310-05 report must end in exactly one LF")

    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise V31005EvidenceError(f"duplicate JSON member {key!r}")
            value[key] = item
        return value

    def nonfinite(value):
        raise V31005EvidenceError(f"non-finite JSON number {value!r}")

    try:
        report = json.loads(
            body[:-1].decode("utf-8", "strict"),
            object_pairs_hook=pairs,
            parse_constant=nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise V31005EvidenceError("V310-05 report is not strict JSON") from exc
    canonical = (json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                 + "\n").encode("utf-8")
    if body != canonical:
        raise V31005EvidenceError("V310-05 report is not canonical JSON")
    return verify_gate_report(report, **expected)


def verify_gate_artifacts(gate_id: str, bodies, *, candidate_identity_digest: str) -> dict:
    """Verify the exact complete artifact family required by one V310-05 release gate."""
    expected = _GATE_ARTIFACTS.get(gate_id)
    if expected is None:
        raise V31005EvidenceError("gate is not owned by the V310-05 evidence contract")
    if not isinstance(bodies, Mapping) or set(bodies) != set(expected):
        raise V31005EvidenceError(
            f"{gate_id} requires exactly the artifacts {sorted(expected)}"
        )
    return {
        kind: read_gate_report(
            bodies[kind],
            gate_id=gate_id,
            artifact_kind=kind,
            candidate_identity_digest=candidate_identity_digest,
        )
        for kind in expected
    }
