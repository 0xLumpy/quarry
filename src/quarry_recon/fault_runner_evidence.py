"""Bounded, non-promoting C-FAULT-RUNNER source contract.

The committed case manifest freezes the exact H0/H1 tests that exercise the
runner's stream, process, cancellation, and publication boundaries.  Its
candidate-labeled companion binds source bytes but makes no execution,
isolation, ownership, signing, or toolchain claim.  It therefore cannot be
used as accepted release evidence.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from types import MappingProxyType

from . import release_evidence as evidence


CASE_MANIFEST_SCHEMA_VERSION = "quarry.fault-runner-case-manifest.v1"
SOURCE_PLAN_SCHEMA_VERSION = "quarry.fault-runner-source-plan.v1"
MAX_BYTES = 1024 * 1024
MAX_INTEGER = (1 << 63) - 1

INPUT_PATHS = MappingProxyType(
    {
        "fault-runner-case-manifest": "release/evidence/fault-runner-cases-v1.json",
        "fault-runner-case-manifest-schema": "release/evidence/schemas/fault-runner-case-manifest-v1.schema.json",
        "fault-runner-source-plan-schema": "release/evidence/schemas/fault-runner-source-plan-v1.schema.json",
        "fault-runner-evidence-runtime": "src/quarry_recon/fault_runner_evidence.py",
        "fault-runner-producer": "scripts/emit_fault_runner_source_plan.py",
        "fault-runner-contract-tests": "tests/test_fault_runner_contract.py",
        "fault-runner-runtime-contract": "src/quarry_recon/contract.py",
        "fault-runner-runtime-runner": "src/quarry_recon/runner.py",
        "fault-runner-runtime-streams": "src/quarry_recon/runner_streams.py",
        "fault-runner-runtime-protocol": "src/quarry_recon/runner_protocol.py",
        "fault-runner-runtime-repository": "src/quarry_recon/runner_repository.py",
        "fault-runner-runtime-supervisor": "src/quarry_recon/runner_supervisor.py",
        "fault-runner-runtime-worker": "src/quarry_recon/runner_worker.py",
        "fault-runner-test-streaming": "tests/test_qr39_001_runner_streaming.py",
        "fault-runner-test-stream-engine": "tests/test_runner_stream_engine.py",
        "fault-runner-test-stderr": "tests/test_runner_stderr.py",
        "fault-runner-test-cancel": "tests/test_runner_cancel.py",
        "fault-runner-test-preflight": "tests/test_runner_preflight.py",
        "fault-runner-test-repository": "tests/test_runner_repository_composition.py",
        "fault-runner-test-parent-validation": "tests/test_runner_protocol_parent_validation.py",
        "fault-runner-contract-doc": "docs/releases/RELEASE-GATES.md",
    }
)


class FaultRunnerEvidenceError(evidence.EvidenceError):
    """The C-FAULT-RUNNER source contract is malformed or overclaims."""


def _case(
    case_id: str,
    boundary: str,
    required_lanes: tuple[str, ...],
    invariant: str,
    *nodeids: str,
) -> dict:
    return {
        "case_id": case_id,
        "boundary": boundary,
        "required_lanes": list(required_lanes),
        "invariant": invariant,
        "nodeids": list(nodeids),
    }


_PARENT_AUTHORITY_NODEIDS = tuple(
    "tests/test_runner_protocol_parent_validation.py::"
    "test_parent_cannot_return_clean_before_every_authority_settles"
    f"[{field}-{value}]"
    for field, value in (
        ("worker_reaped", "False"),
        ("control_eof", "False"),
        ("trailing_control_bytes", "1"),
        ("prepared_identity_verified", "False"),
        ("tool_identity_verified", "False"),
        ("containment_verified", "False"),
        ("containment_bound", "False"),
        ("containment_empty", "False"),
        ("stages_closed", "False"),
        ("worker_returncode", "1"),
        ("expected_worker_pid", "41100"),
        ("expected_launcher_pid", "41101"),
        ("expected_launcher_pgid", "41101"),
        ("expected_containment_kind", "pgid"),
        ("expected_containment_id", "different/containment"),
    )
)

CASES = (
    _case(
        "blocked-input-boundary",
        "blocked-stdin",
        ("H1-tool-integration",),
        "an unread input pipe and its feeder settle within one bounded return",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_a_child_that_ignores_a_large_stdin_returns_promptly",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_an_abandoned_stdin_feeder_does_not_leak",
    ),
    _case(
        "blocked-output-boundary",
        "blocked-output-pipes",
        ("H0-hermetic", "H1-tool-integration"),
        "large simultaneous stdout and stderr are drained without deadlock or unbounded buffering",
        "tests/test_runner_stream_engine.py::"
        "test_large_data_stdin_and_simultaneous_outputs_do_not_deadlock",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_large_stdout_streams_without_a_parent_rss_spike",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_block_signature_early_in_a_large_stderr_is_still_seen",
    ),
    _case(
        "escaped-output-boundary",
        "escaped-output-holders",
        ("H1-tool-integration",),
        "escaped stdout drain is bounded and digested; incomplete stdout and stderr drains are explicitly flagged rather than silently complete",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_an_incomplete_stderr_drain_is_not_authoritative",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_escaped_pipe_holder_is_bounded_flagged_and_digested",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_a_detached_stderr_writer_is_flagged_not_falsely_complete",
    ),
    _case(
        "sink-failure-boundary",
        "sink-write-and-disk-full",
        ("H1-tool-integration",),
        "stdout sink faults retain an owned partial, stderr faults use a distinct terminal field, and prior stderr stays non-current",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_a_publication_write_failure_is_partial_and_owns_a_unique_partial",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_a_stdout_fault_and_partial_are_durable_in_the_terminal_event",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_a_stderr_partial_is_durable_in_its_own_terminal_field",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_a_diagnostic_stderr_fault_does_not_contradict_a_clean_terminal",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_an_unwritable_destination_yields_exactly_one_publication_fault",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_stderr_failure_preserves_prior_evidence_and_flags_currency",
    ),
    _case(
        "output-cap-boundary",
        "output-cap",
        ("H0-hermetic", "H1-tool-integration"),
        "an observed stream beyond its cap retains the exact prefix but cannot validate complete",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_hit_output_cap_is_a_typed_partial_and_preserves_prior_final[0]",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_hit_output_cap_is_a_typed_partial_and_preserves_prior_final[3]",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_hit_cap_is_durable_in_the_contract_terminal_event",
        "tests/test_runner_stream_engine.py::"
        "test_stdout_cap_retains_exact_prefix_but_observes_complete_stream[None-a\\nbc-eof]",
        "tests/test_runner_stream_engine.py::"
        "test_stdout_cap_retains_exact_prefix_but_observes_complete_stream[0--capped]",
        "tests/test_runner_stream_engine.py::"
        "test_stdout_cap_retains_exact_prefix_but_observes_complete_stream[2-a\\n-capped]",
        "tests/test_runner_stream_engine.py::"
        "test_stdout_cap_retains_exact_prefix_but_observes_complete_stream[4-a\\nbc-eof]",
        "tests/test_runner_protocol_parent_validation.py::"
        "test_capped_stage_must_equal_the_exact_requested_prefix_length[3-ab]",
        "tests/test_runner_protocol_parent_validation.py::"
        "test_capped_stage_must_equal_the_exact_requested_prefix_length[3-abcd]",
    ),
    _case(
        "invalid-bytes-boundary",
        "invalid-bytes",
        ("H1-tool-integration",),
        "non-UTF-8 stdout remains exact binary evidence instead of crashing or being recoded",
        "tests/test_qr39_001_runner_streaming.py::test_non_utf8_stdout_never_crashes_the_run",
    ),
    _case(
        "timeout-boundary",
        "timeout",
        ("H0-hermetic", "H1-tool-integration"),
        "timeout records one explicit terminal while preserving the exact drained prefixes",
        "tests/test_runner_stream_engine.py::"
        "test_finite_execution_deadline_times_out_once_and_retains_prefix",
        "tests/test_runner_stderr.py::TestRunnerStderrPath::"
        "test_stderr_is_persisted_on_the_timeout_kill_path",
    ),
    _case(
        "signal-boundary",
        "signal",
        ("H1-tool-integration",),
        "a signaled child is explicit partial with its current bytes and negative signal exit",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_a_signaled_child_is_explicit_partial_and_keeps_current_bytes",
    ),
    _case(
        "empty-command-boundary",
        "empty-command",
        ("H0-hermetic", "H1-tool-integration"),
        "empty argv refuses before effects while clean empty output follows the explicit ok-empty policy",
        "tests/test_runner_preflight.py::"
        "test_invalid_argv_is_typed_and_has_no_filesystem_or_process_side_effect[argv0]",
        "tests/test_runner_preflight.py::"
        "test_invalid_argv_is_typed_and_has_no_filesystem_or_process_side_effect[argv6]",
        "tests/test_qr39_001_runner_streaming.py::"
        "test_ok_empty_false_makes_a_clean_empty_run_a_failure",
    ),
    _case(
        "cancellation-boundary",
        "cancellation",
        ("H1-tool-integration",),
        "successful cancellation and exceptional teardown leave no reachable process tree; stubborn children share one grace deadline and caller lanes return when termination fails",
        "tests/test_runner_cancel.py::test_cancel_all_terminates_a_running_child_within_a_bound",
        "tests/test_runner_cancel.py::test_no_process_survives_cancellation",
        "tests/test_runner_cancel.py::test_an_unexpected_exception_never_orphans_a_running_child",
        "tests/test_runner_cancel.py::test_an_exited_leader_does_not_leave_its_process_group_alive",
        "tests/test_runner_cancel.py::test_stubborn_children_share_one_grace_deadline",
        "tests/test_runner_cancel.py::test_lane_returns_even_when_termination_fails",
    ),
    _case(
        "publication-settlement-boundary",
        "drain-and-publication",
        ("H0-hermetic",),
        "publication requires exact stage, process, containment, and repository settlement authority",
        "tests/test_runner_repository_composition.py::"
        "test_clean_execution_holds_claim_then_publishes_exact_requested_stdout",
        "tests/test_runner_repository_composition.py::"
        "test_nonclean_execution_fences_settled_bytes_and_preserves_prior_final",
        "tests/test_runner_repository_composition.py::"
        "test_later_publication_failure_returns_exact_committed_partition",
        "tests/test_runner_repository_composition.py::"
        "test_unreaped_execution_keeps_durable_claim_and_publishes_nothing",
        "tests/test_runner_repository_composition.py::"
        "test_expired_shared_deadline_fences_settled_stage_before_publication",
        *_PARENT_AUTHORITY_NODEIDS,
        "tests/test_runner_protocol_parent_validation.py::"
        "test_requested_empty_sink_still_needs_empty_digest_and_claim",
        "tests/test_runner_protocol_parent_validation.py::"
        "test_sink_error_can_authenticate_a_prefix_but_never_be_clean",
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
    raise FaultRunnerEvidenceError(f"floating point JSON value is forbidden: {value}")


def _bounded_int(value: str) -> int:
    if len(value.lstrip("-")) > 19:
        raise FaultRunnerEvidenceError("JSON integer exceeds the bounded decimal width")
    parsed = int(value)
    if abs(parsed) > MAX_INTEGER:
        raise FaultRunnerEvidenceError("JSON integer exceeds the supported range")
    return parsed


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FaultRunnerEvidenceError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _same_json_type(left: object, right: object) -> bool:
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
        raise FaultRunnerEvidenceError(
            "fault-runner JSON bytes are absent or out of bounds"
        )
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_int=_bounded_int,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except FaultRunnerEvidenceError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise FaultRunnerEvidenceError("fault-runner JSON is invalid") from exc
    if type(document) is not dict:
        raise FaultRunnerEvidenceError("fault-runner document must be an object")
    if raw != _canonical(document):
        raise FaultRunnerEvidenceError("fault-runner JSON is not canonical")
    return document


def case_manifest_document() -> dict:
    return {
        "schema_version": CASE_MANIFEST_SCHEMA_VERSION,
        "gate_id": "C-FAULT-RUNNER",
        "release": "0.3.10",
        "disposition": "source_substrate",
        "closure_status": "OPEN",
        "semantic_promotion": False,
        "case_count": CASE_COUNT,
        "node_count": NODE_COUNT,
        "cases": [dict(case) for case in CASES],
        "open_reasons": [
            "accepted signed H0 and H1 execution outcomes are absent",
            "candidate ownership, isolation intervals and toolchains are unauthenticated",
        ],
    }


def canonical_case_manifest_bytes() -> bytes:
    return _canonical(case_manifest_document())


def read_case_manifest(raw: bytes) -> dict:
    document = _parse(raw)
    if not _same_json_type(document, case_manifest_document()):
        raise FaultRunnerEvidenceError(
            "fault-runner case manifest differs from the frozen v1 roster"
        )
    return document


def _input_bindings(input_bodies: Mapping[str, bytes]) -> list[dict]:
    if set(input_bodies) != set(INPUT_PATHS):
        raise FaultRunnerEvidenceError(
            "fault-runner input bodies are not the exact source set"
        )
    bindings = []
    for name, path in INPUT_PATHS.items():
        raw = input_bodies[name]
        if type(raw) is not bytes or not raw:
            raise FaultRunnerEvidenceError(f"fault-runner input {name!r} is absent")
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
        raise FaultRunnerEvidenceError("candidate identity digest is invalid")
    bindings = _input_bindings(input_bodies)
    read_case_manifest(input_bodies["fault-runner-case-manifest"])
    cases = [
        {
            **dict(case),
            "execution_status": "not_executed",
            "outcome_digest": None,
        }
        for case in CASES
    ]
    return {
        "schema_version": SOURCE_PLAN_SCHEMA_VERSION,
        "gate_id": "C-FAULT-RUNNER",
        "release": "0.3.10",
        "candidate_identity_digest": candidate_identity_digest,
        "disposition": "source_substrate",
        "closure_status": "OPEN",
        "semantic_promotion": False,
        "case_manifest_digest": _digest(input_bodies["fault-runner-case-manifest"]),
        "input_bindings": bindings,
        "case_count": CASE_COUNT,
        "node_count": NODE_COUNT,
        "cases": cases,
        "attestation": {
            "required_lanes": ["H0-hermetic", "H1-tool-integration"],
            "execution_claimed": False,
            "signed": False,
            "h0_isolated": False,
            "h1_isolated": False,
            "candidate_ownership_authenticated": False,
            "collection_intervals_authenticated": False,
            "toolchains_authenticated": False,
        },
        "open_reasons": [
            "accepted signed H0 and H1 execution outcomes are absent",
            "candidate ownership, isolation intervals and toolchains are unauthenticated",
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
        raise FaultRunnerEvidenceError(
            "fault-runner source plan differs from exact candidate inputs"
        )
    if accepting:
        raise FaultRunnerEvidenceError(
            "fault-runner source plan is non-promoting and cannot satisfy C-FAULT-RUNNER"
        )
    return expected


def canonical_source_plan_bytes(
    document: object,
    *,
    candidate_identity_digest: str,
    input_bodies: Mapping[str, bytes],
) -> bytes:
    return _canonical(
        verify_source_plan(
            document,
            candidate_identity_digest=candidate_identity_digest,
            input_bodies=input_bodies,
        )
    )


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
    manifest = case_manifest_document()
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://quarry.invalid/schemas/fault-runner-case-manifest-v1.schema.json",
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
                "prefixItems": [{"const": case} for case in CASES],
                "items": False,
            },
        },
    }


def source_plan_schema_document() -> dict:
    cases = [
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
    digest = {
        "type": "string",
        "pattern": "^sha256:[0-9a-f]{64}$",
        "minLength": 71,
        "maxLength": 71,
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://quarry.invalid/schemas/fault-runner-source-plan-v1.schema.json",
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
            "gate_id": {"const": "C-FAULT-RUNNER"},
            "release": {"const": "0.3.10"},
            "candidate_identity_digest": digest,
            "disposition": {"const": "source_substrate"},
            "closure_status": {"const": "OPEN"},
            "semantic_promotion": {"const": False},
            "case_manifest_digest": digest,
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
                            "digest": digest,
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
                "prefixItems": cases,
                "items": False,
            },
            "attestation": {
                "const": {
                    "required_lanes": ["H0-hermetic", "H1-tool-integration"],
                    "execution_claimed": False,
                    "signed": False,
                    "h0_isolated": False,
                    "h1_isolated": False,
                    "candidate_ownership_authenticated": False,
                    "collection_intervals_authenticated": False,
                    "toolchains_authenticated": False,
                }
            },
            "open_reasons": {
                "const": [
                    "accepted signed H0 and H1 execution outcomes are absent",
                    "candidate ownership, isolation intervals and toolchains are unauthenticated",
                ]
            },
        },
    }
