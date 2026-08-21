"""Bounded, non-promoting C-FAULT-STORE source contract.

The committed case manifest names the exact production fault tests that cover
the store commit boundary.  The companion source plan binds those test and
runtime bytes to a candidate, but deliberately does not claim that they ran,
that H0 isolation held, or that a signed evidence instance owned the result.
It is therefore useful release substrate and never an accepted gate artifact.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from types import MappingProxyType

from . import release_evidence as evidence


CASE_MANIFEST_SCHEMA_VERSION = "quarry.fault-store-case-manifest.v1"
SOURCE_PLAN_SCHEMA_VERSION = "quarry.fault-store-source-plan.v1"
MAX_BYTES = 1024 * 1024
MAX_INTEGER = (1 << 63) - 1

INPUT_PATHS = MappingProxyType(
    {
        "fault-store-case-manifest": "release/evidence/fault-store-cases-v1.json",
        "fault-store-case-manifest-schema": "release/evidence/schemas/fault-store-case-manifest-v1.schema.json",
        "fault-store-source-plan-schema": "release/evidence/schemas/fault-store-source-plan-v1.schema.json",
        "fault-store-evidence-runtime": "src/quarry_recon/fault_store_evidence.py",
        "fault-store-producer": "scripts/emit_fault_store_source_plan.py",
        "fault-store-contract-tests": "tests/test_fault_store_contract.py",
        "fault-store-runtime-events": "src/quarry_recon/events.py",
        "fault-store-runtime-privfs": "src/quarry_recon/privfs.py",
        "fault-store-runtime-manifest": "src/quarry_recon/run_manifest.py",
        "fault-store-runtime-store": "src/quarry_recon/store.py",
        "fault-store-test-events": "tests/test_events.py",
        "fault-store-test-privfs": "tests/test_phase1_privfs_core.py",
        "fault-store-test-manifest": "tests/test_run_manifest_contract.py",
        "fault-store-test-mutation": "tests/test_phase1_mutation_authority.py",
        "fault-store-test-artifact-authority": "tests/test_phase1_artifact_claim_authority.py",
        "fault-store-test-repository-authority": "tests/test_phase1_repository_authority.py",
        "fault-store-test-durable-accounting": "tests/test_qr39_004_disk_governor.py",
    }
)


class FaultStoreEvidenceError(evidence.EvidenceError):
    """The C-FAULT-STORE source contract is malformed or overclaims."""


def _case(case_id: str, boundary: str, invariant: str, *nodeids: str) -> dict:
    return {
        "case_id": case_id,
        "boundary": boundary,
        "invariant": invariant,
        "nodeids": list(nodeids),
    }


_SEALED_NODEIDS = tuple(
    "tests/test_phase1_repository_authority.py::"
    "test_every_public_base_mutator_rejects_after_the_base_seal"
    f"[{operation}-{lifecycle}]"
    for operation in (
        "raw_path",
        "record",
        "commit_fault",
        "commit_gap",
        "add",
        "inherit",
        "fresh_artifact_dir",
        "create_artifact_dir",
        "artifact_claim",
        "managed_acquisition_claim",
        "managed_acquisition_discard_claim",
    )
    for lifecycle in ("finalizing", "finished", "finalization_failed")
)

CASES = (
    _case(
        "write-boundary",
        "write",
        "short writes finish one exact row and partial write faults restore the prior bytes",
        "tests/test_phase1_mutation_authority.py::"
        "test_normalized_journal_short_write_completes_exact_row",
        "tests/test_phase1_mutation_authority.py::"
        "test_normalized_journal_fault_rolls_back_exact_prior[write]",
    ),
    _case(
        "flush-boundary",
        "flush",
        "bytes retained by a reported flush fault remain durably charged",
        "tests/test_qr39_004_disk_governor.py::TestDurableByteAccounting::"
        "test_a_flush_failure_keeps_the_retained_bytes_charged",
    ),
    _case(
        "fsync-boundary",
        "fsync",
        "pre-publication fsync faults preserve prior bytes and post-publication faults are uncertain",
        "tests/test_phase1_mutation_authority.py::"
        "test_normalized_journal_fault_rolls_back_exact_prior[fsync]",
        "tests/test_phase1_privfs_core.py::"
        "test_file_fsync_failure_preserves_prior_destination",
        "tests/test_phase1_privfs_core.py::"
        "test_directory_fsync_failure_is_an_uncertain_landed_replace",
    ),
    _case(
        "rename-boundary",
        "rename",
        "a failed rename preserves prior bytes while a landed rename is never reported cleanly failed",
        "tests/test_phase1_privfs_core.py::test_replace_failure_preserves_prior_destination",
        "tests/test_phase1_privfs_core.py::"
        "test_rename_that_lands_then_raises_is_not_reported_as_clean_failure",
    ),
    _case(
        "manifest-boundary",
        "manifest",
        "the canonical manifest commits exact base bytes and all seven frozen semantic corruptions fail closed",
        "tests/test_run_manifest_contract.py::"
        "test_writer_emits_one_canonical_reconciled_v1_manifest",
        *(
            "tests/test_run_manifest_contract.py::"
            f"test_semantic_manifest_corruption_refuses_every_consumer[{label}]"
            for label in (
                "extra-keys",
                "schema-version",
                "entity-counts",
                "tools-failed",
                "verdict",
                "generation",
                "base-files",
            )
        ),
    ),
    _case(
        "event-sink-boundary",
        "event-sink",
        "event loss is recorded immediately, survives resume and degrades the manifest",
        "tests/test_events.py::TestSinkFailureRecorded::"
        "test_failed_write_is_recorded_not_swallowed",
        "tests/test_events.py::TestDegradationDurableAcrossResume::"
        "test_degradation_persisted_at_failure_time_without_manual_persist",
        "tests/test_events.py::TestManifestSurfacesDegraded::"
        "test_manifest_records_degradation",
    ),
    _case(
        "reopen-boundary",
        "reopen",
        "reopen preserves degradation and classifies the three frozen torn-suffix classes as durable gaps",
        "tests/test_events.py::TestDegradationDurableAcrossResume::"
        "test_persisted_degradation_reloaded_on_reconfigure",
        "tests/test_phase1_mutation_authority.py::"
        "test_torn_normalized_suffix_is_degraded_and_gaps_verdict[partial-object]",
        "tests/test_phase1_mutation_authority.py::"
        "test_torn_normalized_suffix_is_degraded_and_gaps_verdict[missing-newline]",
        "tests/test_phase1_mutation_authority.py::"
        "test_torn_normalized_suffix_is_degraded_and_gaps_verdict[partial-utf8]",
    ),
    _case(
        "seal-boundary",
        "seal",
        "all eleven frozen public base mutators and authority-owned claim/event paths refuse without mutation after sealing",
        *_SEALED_NODEIDS,
        "tests/test_phase1_artifact_claim_authority.py::"
        "test_path_scoped_claim_refuses_after_seal_without_a_stage_side_effect",
        "tests/test_phase1_artifact_claim_authority.py::"
        "test_event_sink_uses_run_authority_and_cannot_append_after_the_seal",
    ),
    _case(
        "close-reconciliation",
        "close",
        "reported post-durability close faults remain explicit while preserving exact committed bytes",
        "tests/test_phase1_mutation_authority.py::"
        "test_normalized_journal_fault_rolls_back_exact_prior[close]",
        "tests/test_phase1_privfs_core.py::"
        "test_post_durability_close_failure_is_explicit_but_committed",
    ),
)

CASE_COUNT = len(CASES)
NODE_COUNT = sum(len(case["nodeids"]) for case in CASES)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(document: object) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _reject_float(value: str):
    raise FaultStoreEvidenceError(f"floating point JSON value is forbidden: {value}")


def _bounded_int(value: str) -> int:
    if len(value.lstrip("-")) > 19:
        raise FaultStoreEvidenceError("JSON integer exceeds the bounded decimal width")
    parsed = int(value)
    if abs(parsed) > MAX_INTEGER:
        raise FaultStoreEvidenceError("JSON integer exceeds the supported range")
    return parsed


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FaultStoreEvidenceError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _same_json_type(left: object, right: object) -> bool:
    """Compare parsed JSON without Python's bool/int or int/float coercions."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(
            _same_json_type(left[key], right[key]) for key in left
        )
    if type(left) is list:
        return len(left) == len(right) and all(
            _same_json_type(a, b) for a, b in zip(left, right)
        )
    return left == right


def _parse(raw: bytes) -> dict:
    if type(raw) is not bytes or not raw or len(raw) > MAX_BYTES:
        raise FaultStoreEvidenceError(
            "fault-store JSON bytes are absent or out of bounds"
        )
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_int=_bounded_int,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except FaultStoreEvidenceError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise FaultStoreEvidenceError("fault-store JSON is invalid") from exc
    if type(document) is not dict:
        raise FaultStoreEvidenceError("fault-store document must be an object")
    if raw != _canonical(document):
        raise FaultStoreEvidenceError("fault-store JSON is not canonical")
    return document


def case_manifest_document() -> dict:
    return {
        "schema_version": CASE_MANIFEST_SCHEMA_VERSION,
        "gate_id": "C-FAULT-STORE",
        "release": "0.3.10",
        "disposition": "source_substrate",
        "closure_status": "OPEN",
        "semantic_promotion": False,
        "case_count": CASE_COUNT,
        "node_count": NODE_COUNT,
        "cases": [dict(case) for case in CASES],
        "open_reasons": [
            "accepted signed H0 execution outcomes are absent",
            "candidate ownership, isolation interval and toolchain are unauthenticated",
        ],
    }


def canonical_case_manifest_bytes() -> bytes:
    return _canonical(case_manifest_document())


def read_case_manifest(raw: bytes) -> dict:
    document = _parse(raw)
    if not _same_json_type(document, case_manifest_document()):
        raise FaultStoreEvidenceError(
            "fault-store case manifest differs from the frozen v1 roster"
        )
    return document


def _input_bindings(input_bodies: Mapping[str, bytes]) -> list[dict]:
    if set(input_bodies) != set(INPUT_PATHS):
        raise FaultStoreEvidenceError(
            "fault-store input bodies are not the exact source set"
        )
    bindings = []
    for name, path in INPUT_PATHS.items():
        raw = input_bodies[name]
        if type(raw) is not bytes or not raw:
            raise FaultStoreEvidenceError(f"fault-store input {name!r} is absent")
        bindings.append({"name": name, "path": path, "digest": _digest(raw)})
    return bindings


def build_source_plan(
    *,
    candidate_identity_digest: str,
    input_bodies: Mapping[str, bytes],
) -> dict:
    if (
        type(candidate_identity_digest) is not str
        or len(candidate_identity_digest) != 71
        or not candidate_identity_digest.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in candidate_identity_digest[7:])
    ):
        raise FaultStoreEvidenceError("candidate identity digest is invalid")
    bindings = _input_bindings(input_bodies)
    read_case_manifest(input_bodies["fault-store-case-manifest"])
    cases = []
    for case in CASES:
        cases.append(
            {
                **dict(case),
                "execution_status": "not_executed",
                "outcome_digest": None,
            }
        )
    return {
        "schema_version": SOURCE_PLAN_SCHEMA_VERSION,
        "gate_id": "C-FAULT-STORE",
        "release": "0.3.10",
        "candidate_identity_digest": candidate_identity_digest,
        "disposition": "source_substrate",
        "closure_status": "OPEN",
        "semantic_promotion": False,
        "case_manifest_digest": _digest(input_bodies["fault-store-case-manifest"]),
        "input_bindings": bindings,
        "case_count": CASE_COUNT,
        "node_count": NODE_COUNT,
        "cases": cases,
        "attestation": {
            "required_lane": "H0-hermetic",
            "execution_claimed": False,
            "signed": False,
            "h0_isolated": False,
            "candidate_ownership_authenticated": False,
            "collection_interval_authenticated": False,
            "toolchain_authenticated": False,
        },
        "open_reasons": [
            "accepted signed H0 execution outcomes are absent",
            "candidate ownership, isolation interval and toolchain are unauthenticated",
        ],
    }


def verify_source_plan(
    document: object,
    *,
    candidate_identity_digest: str,
    input_bodies: Mapping[str, bytes],
    accepting: bool = False,
) -> dict:
    expected = build_source_plan(
        candidate_identity_digest=candidate_identity_digest,
        input_bodies=input_bodies,
    )
    if not _same_json_type(document, expected):
        raise FaultStoreEvidenceError(
            "fault-store source plan differs from exact candidate inputs"
        )
    if accepting:
        raise FaultStoreEvidenceError(
            "fault-store source plan is non-promoting and cannot satisfy C-FAULT-STORE",
        )
    return expected


def canonical_source_plan_bytes(
    document: object,
    *,
    candidate_identity_digest: str,
    input_bodies: Mapping[str, bytes],
) -> bytes:
    verified = verify_source_plan(
        document,
        candidate_identity_digest=candidate_identity_digest,
        input_bodies=input_bodies,
    )
    return _canonical(verified)


def read_source_plan(
    raw: bytes,
    *,
    candidate_identity_digest: str,
    input_bodies: Mapping[str, bytes],
    accepting: bool = False,
) -> dict:
    return verify_source_plan(
        _parse(raw),
        candidate_identity_digest=candidate_identity_digest,
        input_bodies=input_bodies,
        accepting=accepting,
    )


def case_manifest_schema_document() -> dict:
    case_prefixes = [{"const": case} for case in CASES]
    manifest = case_manifest_document()
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://quarry.invalid/schemas/fault-store-case-manifest-v1.schema.json",
        "type": "object",
        "additionalProperties": False,
        "const": manifest,
        "properties": {
            **{
                key: {"const": value}
                for key, value in manifest.items()
                if key != "cases"
            },
            "cases": {
                "type": "array",
                "minItems": CASE_COUNT,
                "maxItems": CASE_COUNT,
                "prefixItems": case_prefixes,
                "items": False,
            },
        },
    }


def source_plan_schema_document() -> dict:
    case_prefixes = [
        {
            "type": "object",
            "properties": {
                **{key: {"const": value} for key, value in case.items()},
                "execution_status": {"const": "not_executed"},
                "outcome_digest": {"type": "null"},
            },
            "required": [*case, "execution_status", "outcome_digest"],
            "additionalProperties": False,
        }
        for case in CASES
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://quarry.invalid/schemas/fault-store-source-plan-v1.schema.json",
        "type": "object",
        "required": [
            "schema_version",
            "gate_id",
            "release",
            "candidate_identity_digest",
            "disposition",
            "closure_status",
            "semantic_promotion",
            "case_manifest_digest",
            "input_bindings",
            "case_count",
            "node_count",
            "cases",
            "attestation",
            "open_reasons",
        ],
        "additionalProperties": False,
        "properties": {
            "schema_version": {"const": SOURCE_PLAN_SCHEMA_VERSION},
            "gate_id": {"const": "C-FAULT-STORE"},
            "release": {"const": "0.3.10"},
            "candidate_identity_digest": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
                "minLength": 71,
                "maxLength": 71,
            },
            "disposition": {"const": "source_substrate"},
            "closure_status": {"const": "OPEN"},
            "semantic_promotion": {"const": False},
            "case_manifest_digest": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
                "minLength": 71,
                "maxLength": 71,
            },
            "input_bindings": {
                "type": "array",
                "minItems": len(INPUT_PATHS),
                "maxItems": len(INPUT_PATHS),
                "prefixItems": [
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["name", "path", "digest"],
                        "properties": {
                            "name": {"const": name},
                            "path": {"const": path},
                            "digest": {
                                "type": "string",
                                "pattern": "^sha256:[0-9a-f]{64}$",
                                "minLength": 71,
                                "maxLength": 71,
                            },
                        },
                    }
                    for name, path in INPUT_PATHS.items()
                ],
                "items": False,
            },
            "case_count": {"const": CASE_COUNT},
            "node_count": {"const": NODE_COUNT},
            "cases": {
                "type": "array",
                "minItems": CASE_COUNT,
                "maxItems": CASE_COUNT,
                "prefixItems": case_prefixes,
                "items": False,
            },
            "attestation": {
                "const": {
                    "required_lane": "H0-hermetic",
                    "execution_claimed": False,
                    "signed": False,
                    "h0_isolated": False,
                    "candidate_ownership_authenticated": False,
                    "collection_interval_authenticated": False,
                    "toolchain_authenticated": False,
                }
            },
            "open_reasons": {
                "const": [
                    "accepted signed H0 execution outcomes are absent",
                    "candidate ownership, isolation interval and toolchain are unauthenticated",
                ]
            },
        },
    }
