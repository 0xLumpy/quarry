"""Adversarial checks for the parent side of the Phase-1 worker protocol.

The worker is a killable capture owner, not the publication authority.  A structurally
valid worker settlement therefore cannot authorize clean publication until the parent
has bound it to the process it started, the containment it owns, control-channel EOF,
and parent-authenticated proofs of the exact staged bytes.
"""
from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import replace

import pytest

from quarry_recon import runner_protocol as protocol


pytestmark = pytest.mark.offline

RID = "01" * 16
OTHER_RID = "02" * 16
SYNTHETIC_CLAIM = "03" * 16
WORKER_PID = 41001
TOOL_PID = 41002
CGROUP_ID = "quarry/run-01/attempt-01"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _invocation(tmp_path, **overrides):
    values = {
        "request_id": RID,
        "tool": "fixture",
        "cmd": ["/usr/bin/printf", "%s", "evidence"],
        "timeout": 30,
        "stdin_data": None,
        "input_file": None,
        "ok_empty": True,
        "ok_codes": (0,),
        "env": {"QUARRY_TEST_SECRET": "never-render-this"},
        "base_environment": {"PATH": "/usr/bin"},
        "cwd": tmp_path,
        "raw_path": tmp_path / "stdout.final",
        "stderr_path": tmp_path / "stderr.final",
        "max_output_bytes": None,
    }
    values.update(overrides)
    return protocol.normalize_invocation(**values)


def _stream(role, terminal, *, observed=b"", retained=None, lines=0, claim_id=None,
            observed_digest=..., retained_digest=...):
    if observed_digest is ...:
        observed_digest = _digest(observed)
    if retained is None:
        retained = b""
    if retained_digest is ...:
        retained_digest = _digest(retained) if claim_id is not None else None
    return protocol.StreamSettlement(
        role=role,
        terminal=terminal,
        observed_bytes=len(observed),
        retained_bytes=len(retained),
        observed_sha256=observed_digest,
        retained_sha256=retained_digest,
        lines=lines,
        detail=None,
        claim_id=claim_id,
    )


def _descriptor_claim(request, role):
    return next(claim for claim in request.descriptor_claims if claim.role is role)


def _proof(request, role, data):
    claim = _descriptor_claim(request, role)
    return protocol.DescriptorProof(
        role=role,
        claim_id=claim.claim_id,
        size=len(data),
        sha256=_digest(data),
        lines=None if role is protocol.StreamRole.STDIN else data.count(b"\n"),
    )


def _settlement(streams, **overrides):
    values = {
        "request_id": RID,
        "terminal": protocol.ExecutionTerminal.COMPLETE,
        "launched": True,
        "exit_code": 0,
        "process_group_settled": True,
        # This is worker testimony.  Parent validation must never treat it as
        # independent proof that a setsid() descendant did not escape the PGID.
        "process_tree_settled": True,
        "streams": tuple(streams),
        "worker_pid": WORKER_PID,
        "tool_pid": TOOL_PID,
        "detail": None,
    }
    values.update(overrides)
    return protocol.WorkerSettlement(**values)


def _ready(**overrides):
    values = {"request_id": RID, "worker_pid": WORKER_PID}
    values.update(overrides)
    return protocol.ReadyFrame(**values)


def _prepared(**overrides):
    values = {
        "request_id": RID,
        "worker_pid": WORKER_PID,
        "launcher_pid": TOOL_PID,
        "launcher_pgid": TOOL_PID,
        "containment_kind": protocol.ContainmentKind.CGROUP_V2,
        "containment_id": CGROUP_ID,
    }
    values.update(overrides)
    return protocol.PreparedFrame(**values)


def _started(**overrides):
    values = {
        "request_id": RID,
        "worker_pid": WORKER_PID,
        "tool_pid": TOOL_PID,
        "tool_pgid": TOOL_PID,
        "containment_kind": protocol.ContainmentKind.CGROUP_V2,
        "containment_id": CGROUP_ID,
    }
    values.update(overrides)
    return protocol.StartedFrame(**values)


def _clean_case(tmp_path, *, stdin_data=None, input_file=None,
                stdin_file_bytes=None, stdout=b"evidence\n", stderr=b"",
                max_output_bytes=None, containment_kind=None):
    invocation = _invocation(tmp_path, stdin_data=stdin_data,
                             input_file=input_file,
                             max_output_bytes=max_output_bytes)
    out_claim = _descriptor_claim(invocation.worker, protocol.StreamRole.STDOUT)
    err_claim = _descriptor_claim(invocation.worker, protocol.StreamRole.STDERR)
    out_proof = _proof(invocation.worker, protocol.StreamRole.STDOUT, stdout)
    err_proof = _proof(invocation.worker, protocol.StreamRole.STDERR, stderr)
    proofs = []
    if input_file is not None:
        if type(stdin_file_bytes) is not bytes:
            raise AssertionError("file-stdin fixtures need exact source bytes")
        stdin_bytes = stdin_file_bytes
        proofs.append(_proof(invocation.worker, protocol.StreamRole.STDIN,
                             stdin_file_bytes))
    elif stdin_data is None:
        stdin_bytes = b""
    else:
        stdin_bytes = stdin_data.encode("utf-8")
    proofs.extend((out_proof, err_proof))
    streams = (
        _stream(protocol.StreamRole.STDIN, protocol.StreamTerminal.COMPLETE,
                observed=stdin_bytes),
        _stream(protocol.StreamRole.STDOUT, protocol.StreamTerminal.EOF,
                observed=stdout, retained=stdout, lines=stdout.count(b"\n"),
                claim_id=out_claim.claim_id),
        _stream(protocol.StreamRole.STDERR, protocol.StreamTerminal.EOF,
                observed=stderr, retained=stderr, lines=stderr.count(b"\n"),
                claim_id=err_claim.claim_id),
    )
    settlement = _settlement(streams)
    kind = containment_kind or protocol.ContainmentKind.CGROUP_V2
    containment_id = CGROUP_ID if kind is protocol.ContainmentKind.CGROUP_V2 else str(TOOL_PID)
    ready = _ready()
    prepared = _prepared(containment_kind=kind, containment_id=containment_id)
    started = _started(containment_kind=kind, containment_id=containment_id)
    context = protocol.ParentSettlementContext(
        request=invocation.worker,
        ready=ready,
        prepared=prepared,
        started=started,
        settlement=settlement,
        descriptor_proofs=tuple(proofs),
        expected_worker_pid=WORKER_PID,
        expected_launcher_pid=TOOL_PID,
        expected_launcher_pgid=TOOL_PID,
        expected_containment_kind=kind,
        expected_containment_id=containment_id,
        worker_returncode=0,
        worker_reaped=True,
        control_eof=True,
        trailing_control_bytes=0,
        prepared_identity_verified=True,
        tool_identity_verified=True,
        containment_verified=True,
        containment_bound=True,
        containment_empty=True,
        stages_closed=True,
    )
    return context


def _assert_refused_or_unclean(thunk):
    """Permit a malformed context to be rejected or represented as typed degradation."""
    try:
        result = thunk()
    except protocol.ProtocolError:
        return
    assert result.capture_complete is False


def _frame(doc):
    payload = json.dumps(doc, separators=(",", ":")).encode("utf-8")
    return struct.pack(">I", len(payload)) + payload


# -- Boundary inputs must never escape as ambient Python errors -----------------


@pytest.mark.parametrize("bad_codes", [([],), ({},), (set(),)])
def test_unhashable_exit_codes_are_typed_protocol_failures(tmp_path, bad_codes):
    with pytest.raises(protocol.ProtocolError):
        _invocation(tmp_path, ok_codes=bad_codes)
    request = _invocation(tmp_path).worker
    with pytest.raises(protocol.ProtocolError):
        replace(request, ok_codes=bad_codes)


def test_unhashable_exit_code_from_wire_is_a_typed_protocol_failure(tmp_path):
    body = _invocation(tmp_path).worker.to_dict()
    body["ok_codes"] = [[]]
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_request(_frame({
            "version": protocol.PROTOCOL_VERSION,
            "kind": "request",
            "body": body,
        }))


@pytest.mark.parametrize("timeout", [10 ** 10_000, -(10 ** 10_000), -0.0],
                         ids=("positive", "negative", "negative-zero"))
def test_pathological_integer_timeouts_are_typed_and_bounded(tmp_path, timeout):
    with pytest.raises(protocol.ProtocolError):
        _invocation(tmp_path, timeout=timeout)


@pytest.mark.parametrize("sign", [b"", b"-"])
def test_json_integer_parsing_is_bounded_before_model_construction(sign):
    assert protocol.MAX_JSON_INTEGER_DIGITS + 128 < protocol.MAX_FRAME_BYTES
    digits = b"9" * (protocol.MAX_JSON_INTEGER_DIGITS + 1)
    payload = b'{"version":' + sign + digits + b',"kind":"request","body":{}}'
    frame = struct.pack(">I", len(payload)) + payload
    with pytest.raises(protocol.ProtocolError, match="integer"):
        protocol.decode_request(frame)


@pytest.mark.parametrize("lexical", (b"1e-10000", b"-0.0", b"-0"))
def test_float_underflow_and_negative_zero_cannot_become_unlimited_timeout(
        tmp_path, lexical):
    body = _invocation(tmp_path).worker.to_dict()
    marker = b'"timeout":30'
    encoded = json.dumps({
        "version": protocol.PROTOCOL_VERSION,
        "kind": "request",
        "body": body,
    }, separators=(",", ":")).encode("utf-8")
    assert marker in encoded
    encoded = encoded.replace(marker, b'"timeout":' + lexical, 1)
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_request(struct.pack(">I", len(encoded)) + encoded)


def test_data_stdin_size_bound_is_identical_for_direct_and_wire_requests(tmp_path):
    request = _invocation(tmp_path, stdin_data="x").worker
    too_large = protocol.MAX_STDIN_DATA_BYTES + 1
    with pytest.raises(protocol.ProtocolError, match="stdin exceeds"):
        replace(request, stdin_bytes=too_large)
    body = request.to_dict()
    body["stdin_bytes"] = too_large
    with pytest.raises(protocol.ProtocolError, match="stdin exceeds"):
        protocol.WorkerRequest.from_dict(body)


def test_aggregate_argv_and_environment_are_bounded_before_encoding(tmp_path):
    assert protocol.MAX_ARGV_BYTES <= protocol.MAX_FRAME_BYTES
    assert protocol.MAX_ENV_BYTES <= protocol.MAX_FRAME_BYTES
    unit = "x" * 4096
    argv = ["tool"] + [unit] * (protocol.MAX_ARGV_BYTES // len(unit) + 1)
    with pytest.raises(protocol.ProtocolError):
        _invocation(tmp_path, cmd=argv)
    count = protocol.MAX_ENV_BYTES // (len(unit) + 16) + 2
    environment = {f"K{i}": unit for i in range(count)}
    with pytest.raises(protocol.ProtocolError):
        _invocation(tmp_path, env=environment)


def test_direct_request_aggregate_refusal_precedes_monolithic_json_allocation(
        tmp_path, monkeypatch):
    request = _invocation(tmp_path).worker
    unit = "x" * 4096
    oversized = ("tool",) + (unit,) * (protocol.MAX_ARGV_BYTES // len(unit) + 1)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("aggregate validation attempted monolithic JSON encoding")

    monkeypatch.setattr(protocol.json, "dumps", forbidden)
    with pytest.raises(protocol.ProtocolError, match="aggregate"):
        replace(request, argv=oversized)


# -- Stream records cannot contain internally contradictory evidence -----------


def test_equal_observed_and_retained_bytes_require_the_same_digest():
    with pytest.raises(protocol.ProtocolError):
        _stream(protocol.StreamRole.STDOUT, protocol.StreamTerminal.EOF,
                observed=b"abc", retained=b"xyz", claim_id=SYNTHETIC_CLAIM)


@pytest.mark.parametrize("observed,lines", [(b"", 1), (b"x", 2)])
def test_line_count_cannot_exceed_observed_bytes(observed, lines):
    with pytest.raises(protocol.ProtocolError):
        _stream(protocol.StreamRole.STDOUT, protocol.StreamTerminal.EOF,
                observed=observed, lines=lines)


def test_stdin_and_unretained_output_cannot_carry_artifact_claims():
    with pytest.raises(protocol.ProtocolError):
        _stream(protocol.StreamRole.STDIN, protocol.StreamTerminal.COMPLETE,
                claim_id=SYNTHETIC_CLAIM)
    with pytest.raises(protocol.ProtocolError):
        _stream(protocol.StreamRole.STDOUT, protocol.StreamTerminal.EOF,
                claim_id=SYNTHETIC_CLAIM, retained_digest=None)


def test_worker_streams_and_request_claims_have_one_canonical_role_order(tmp_path):
    invocation = _invocation(tmp_path)
    assert tuple(claim.role for claim in invocation.worker.descriptor_claims) == (
        protocol.StreamRole.STDOUT, protocol.StreamRole.STDERR,
    )
    with pytest.raises(protocol.ProtocolError, match="order"):
        _settlement(tuple(reversed(_clean_streams())))


def test_claim_ids_are_deterministic_request_and_role_correlations(tmp_path):
    first = _invocation(tmp_path).worker.descriptor_claims
    again = _invocation(tmp_path).worker.descriptor_claims
    other = _invocation(tmp_path, request_id=OTHER_RID).worker.descriptor_claims
    assert first == again
    assert len({claim.claim_id for claim in first}) == len(first)
    assert tuple(claim.claim_id for claim in first) != tuple(
        claim.claim_id for claim in other)
    assert all(claim.claim_id != RID for claim in first)


def test_direct_and_wire_requests_cannot_substitute_derived_claim_identity(tmp_path):
    request = _invocation(tmp_path).worker
    claims = list(request.descriptor_claims)
    claims[0] = replace(claims[0], claim_id=SYNTHETIC_CLAIM)
    with pytest.raises(protocol.ProtocolError, match="bind request"):
        replace(request, descriptor_claims=tuple(claims))
    body = request.to_dict()
    body["descriptor_claims"][0]["claim_id"] = SYNTHETIC_CLAIM
    with pytest.raises(protocol.ProtocolError, match="bind request"):
        protocol.WorkerRequest.from_dict(body)


def test_descriptor_claims_cross_the_wire_but_parent_proofs_do_not(tmp_path):
    request = _invocation(tmp_path).worker
    decoded = protocol.decode_request(protocol.encode_request(request))
    assert decoded.descriptor_claims == request.descriptor_claims
    assert not hasattr(decoded, "descriptor_proofs")


# -- READY/PREPARED/STARTED are strict, ordered, request-bound control frames ---


def test_launch_control_frames_round_trip_with_exact_kinds():
    ready = _ready()
    prepared = _prepared()
    started = _started()
    assert protocol.decode_ready(protocol.encode_ready(ready)) == ready
    assert protocol.decode_prepared(protocol.encode_prepared(prepared)) == prepared
    assert protocol.encode_prepared(protocol.decode_prepared(
        protocol.encode_prepared(prepared))) == protocol.encode_prepared(prepared)
    assert protocol.decode_started(protocol.encode_started(started)) == started
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_started(protocol.encode_ready(ready))
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_started(protocol.encode_prepared(prepared))
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_prepared(protocol.encode_started(started))
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_ready(protocol.encode_started(started))


@pytest.mark.parametrize("mutation", [
    lambda body: body.pop("launcher_pid"),
    lambda body: body.__setitem__("extra", 1),
    lambda body: body.__setitem__("launcher_pid", True),
    lambda body: body.__setitem__("containment_kind", "invented"),
])
def test_prepared_frame_wire_schema_fails_closed(mutation):
    body = _prepared().to_dict()
    mutation(body)
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_prepared(_frame({
            "version": protocol.PROTOCOL_VERSION,
            "kind": "prepared",
            "body": body,
        }))


def test_worker_is_never_the_tool_group_leader():
    with pytest.raises(protocol.ProtocolError, match="outside tool group"):
        _started(worker_pid=TOOL_PID)


def test_worker_and_parked_launcher_are_distinct_identities():
    with pytest.raises(protocol.ProtocolError, match="differ from launcher"):
        _prepared(worker_pid=TOOL_PID)
    with pytest.raises(protocol.ProtocolError, match="group leader"):
        _prepared(launcher_pgid=TOOL_PID + 1)


def test_control_reprs_hide_containment_identifiers():
    prepared = _prepared(containment_id="framework-secret-value")
    started = _started(containment_id="framework-secret-value")
    settlement = _settlement(_clean_streams())
    transcript = protocol.validate_control_sequence(
        (_ready(), prepared, started, settlement))
    assert "framework-secret-value" not in repr(prepared)
    assert "framework-secret-value" not in repr(started)
    assert "framework-secret-value" not in repr(transcript)


@pytest.mark.parametrize("containment_id", ["/absolute", "../escape", "a/../b",
                                              "a//b", "line\nbreak"])
def test_containment_identifiers_are_bounded_safe_correlations(containment_id):
    with pytest.raises(protocol.ProtocolError):
        _started(containment_id=containment_id)
    with pytest.raises(protocol.ProtocolError):
        _prepared(containment_id=containment_id)


def test_launched_and_launch_failed_control_sequences_are_unambiguous():
    streams = tuple(
        _stream(role, protocol.StreamTerminal.CANCELLED,
                observed_digest=None)
        for role in protocol.StreamRole
    )
    launch_failed = _settlement(
        streams,
        terminal=protocol.ExecutionTerminal.LAUNCH_FAILED,
        launched=False,
        exit_code=None,
        process_group_settled=True,
        process_tree_settled=True,
        tool_pid=None,
    )
    launched = protocol.validate_control_sequence(
        (_ready(), _prepared(), _started(), _settlement(_clean_streams())))
    unlaunched = protocol.validate_control_sequence((_ready(), launch_failed))
    prepared_failure = protocol.validate_control_sequence(
        (_ready(), _prepared(), launch_failed))
    assert launched.ready == _ready() and launched.prepared == _prepared()
    assert launched.started == _started()
    assert launched.settlement.launched is True
    assert unlaunched.prepared is None and unlaunched.started is None
    assert unlaunched.settlement.launched is False
    assert prepared_failure.prepared == _prepared()
    assert prepared_failure.started is None
    assert prepared_failure.settlement.launched is False


def test_worker_testimony_never_exposes_parent_cleanliness_properties():
    settlement = _settlement(_clean_streams())
    for attribute in ("capture_complete", "tree_proven"):
        assert not hasattr(settlement, attribute)


def _clean_streams():
    return (
        _stream(protocol.StreamRole.STDIN, protocol.StreamTerminal.COMPLETE),
        _stream(protocol.StreamRole.STDOUT, protocol.StreamTerminal.EOF),
        _stream(protocol.StreamRole.STDERR, protocol.StreamTerminal.EOF),
    )


@pytest.mark.parametrize("frames", [
    lambda: (_started(), _ready(), _settlement(_clean_streams())),
    lambda: (_ready(), _settlement(_clean_streams()), _started()),
    lambda: (_ready(), _started(), _settlement(_clean_streams())),
    lambda: (_ready(), _ready(), _prepared(), _settlement(_clean_streams())),
    lambda: (_ready(), _prepared(), _prepared(), _settlement(_clean_streams())),
    lambda: (_ready(), _prepared(), _started(), _started(),
             _settlement(_clean_streams())),
    lambda: (_ready(), _started()),
])
def test_out_of_order_duplicate_trailing_and_incomplete_sequences_fail(frames):
    with pytest.raises(protocol.ProtocolError):
        protocol.validate_control_sequence(frames())


@pytest.mark.parametrize("frames", [
    (_ready(),),
    (_ready(), _prepared()),
    (_ready(), _prepared(), _started()),
])
def test_worker_crash_before_settlement_never_forms_a_terminal_transcript(frames):
    with pytest.raises(protocol.ProtocolError):
        protocol.validate_control_sequence(frames)


def test_sequence_ids_pids_and_tool_identity_must_agree():
    settlement = _settlement(_clean_streams())
    for frames in (
        (_ready(request_id=OTHER_RID), _prepared(), _started(), settlement),
        (_ready(), _prepared(worker_pid=WORKER_PID + 99), _started(), settlement),
        (_ready(), _prepared(), _started(worker_pid=WORKER_PID + 99), settlement),
        (_ready(), _prepared(),
         _started(tool_pid=TOOL_PID + 1, tool_pgid=TOOL_PID + 1), settlement),
        (_ready(), _prepared(), _started(),
         replace(settlement, tool_pid=TOOL_PID + 1)),
    ):
        with pytest.raises(protocol.ProtocolError):
            protocol.validate_control_sequence(frames)
    with pytest.raises(protocol.ProtocolError):
        _started(tool_pgid=TOOL_PID + 1)


@pytest.mark.parametrize("prepared_change,started_change", [
    ({"request_id": OTHER_RID}, {}),
    ({"launcher_pid": TOOL_PID + 1, "launcher_pgid": TOOL_PID + 1}, {}),
    ({}, {"containment_id": "quarry/other"}),
    ({"containment_kind": protocol.ContainmentKind.PGID,
      "containment_id": str(TOOL_PID)}, {}),
])
def test_prepared_and_started_identity_and_intent_must_match(prepared_change,
                                                            started_change):
    with pytest.raises(protocol.ProtocolError):
        protocol.validate_control_sequence((
            _ready(), _prepared(**prepared_change), _started(**started_change),
            _settlement(_clean_streams()),
        ))


# -- Parent authority binds settlement to stages, stdin, cap, and real process --


def test_cgroup_bound_parent_validation_is_the_only_clean_authority(tmp_path):
    context = _clean_case(tmp_path)
    result = protocol.validate_parent_settlement(context)
    assert result.mechanically_settled is True
    assert result.tree_proven is True
    assert result.capture_complete is True
    assert not hasattr(result, "clean_eligible")


def test_validated_settlement_cannot_be_constructed_without_parent_validator(tmp_path):
    context = _clean_case(tmp_path)
    worker = context.settlement
    with pytest.raises(protocol.ProtocolError, match="authority"):
        protocol.ValidatedSettlement(
            worker=worker, mechanically_settled=True, tree_proven=True,
            capture_complete=True, _authority=object())


@pytest.mark.parametrize("field,value", [
    ("worker_reaped", False),
    ("control_eof", False),
    ("trailing_control_bytes", 1),
    ("prepared_identity_verified", False),
    ("tool_identity_verified", False),
    ("containment_verified", False),
    ("containment_bound", False),
    ("containment_empty", False),
    ("stages_closed", False),
    ("worker_returncode", 1),
    ("expected_worker_pid", WORKER_PID + 99),
    ("expected_launcher_pid", TOOL_PID + 99),
    ("expected_launcher_pgid", TOOL_PID + 99),
    ("expected_containment_kind", protocol.ContainmentKind.PGID),
    ("expected_containment_id", "different/containment"),
])
def test_parent_cannot_return_clean_before_every_authority_settles(tmp_path, field, value):
    context = _clean_case(tmp_path)
    _assert_refused_or_unclean(
        lambda: protocol.validate_parent_settlement(replace(context, **{field: value})))


@pytest.mark.parametrize("terminal", [
    protocol.ExecutionTerminal.LAUNCH_FAILED,
    protocol.ExecutionTerminal.CANCELLED,
])
def test_parent_accepts_prepared_fast_failure_but_never_as_clean(tmp_path, terminal):
    invocation = _invocation(tmp_path)
    streams = tuple(
        _stream(role, protocol.StreamTerminal.CANCELLED,
                observed_digest=None)
        for role in protocol.StreamRole
    )
    context = protocol.ParentSettlementContext(
        request=invocation.worker,
        ready=_ready(),
        prepared=_prepared(),
        started=None,
        settlement=_settlement(
            streams,
            terminal=terminal,
            launched=False,
            exit_code=None,
            process_group_settled=True,
            process_tree_settled=True,
            tool_pid=None,
        ),
        descriptor_proofs=(),
        expected_worker_pid=WORKER_PID,
        expected_launcher_pid=TOOL_PID,
        expected_launcher_pgid=TOOL_PID,
        expected_containment_kind=protocol.ContainmentKind.CGROUP_V2,
        expected_containment_id=CGROUP_ID,
        worker_returncode=0,
        worker_reaped=True,
        control_eof=True,
        trailing_control_bytes=0,
        prepared_identity_verified=True,
        tool_identity_verified=False,
        containment_verified=True,
        containment_bound=True,
        containment_empty=True,
        stages_closed=True,
    )
    result = protocol.validate_parent_settlement(context)
    assert result.mechanically_settled is False
    assert result.tree_proven is False
    assert result.capture_complete is False


def test_unprepared_fast_failure_has_no_launcher_parent_proof(tmp_path):
    invocation = _invocation(tmp_path)
    streams = tuple(
        _stream(role, protocol.StreamTerminal.NOT_STARTED,
                observed_digest=None)
        for role in protocol.StreamRole
    )
    context = protocol.ParentSettlementContext(
        request=invocation.worker,
        ready=_ready(),
        prepared=None,
        started=None,
        settlement=_settlement(
            streams,
            terminal=protocol.ExecutionTerminal.LAUNCH_FAILED,
            launched=False,
            exit_code=None,
            process_group_settled=True,
            process_tree_settled=True,
            tool_pid=None,
        ),
        descriptor_proofs=(),
        expected_worker_pid=WORKER_PID,
        expected_launcher_pid=None,
        expected_launcher_pgid=None,
        expected_containment_kind=protocol.ContainmentKind.CGROUP_V2,
        expected_containment_id=CGROUP_ID,
        worker_returncode=0,
        worker_reaped=True,
        control_eof=True,
        trailing_control_bytes=0,
        prepared_identity_verified=False,
        tool_identity_verified=False,
        containment_verified=True,
        containment_bound=False,
        containment_empty=True,
        stages_closed=True,
    )
    result = protocol.validate_parent_settlement(context)
    assert result.mechanically_settled is False
    assert result.tree_proven is False
    assert result.capture_complete is False


@pytest.mark.parametrize("missing_role", [protocol.StreamRole.STDOUT,
                                          protocol.StreamRole.STDERR])
def test_every_requested_sink_requires_its_exact_parent_proof(tmp_path, missing_role):
    context = _clean_case(tmp_path)
    proofs = tuple(proof for proof in context.descriptor_proofs
                   if proof.role is not missing_role)
    _assert_refused_or_unclean(
        lambda: protocol.validate_parent_settlement(
            replace(context, descriptor_proofs=proofs)))


def test_claim_role_id_size_and_digest_are_parent_authenticated(tmp_path):
    context = _clean_case(tmp_path)
    out, err = context.descriptor_proofs
    for changed in (
        replace(out, role=protocol.StreamRole.STDERR),
        replace(out, claim_id=OTHER_RID),
        replace(out, size=out.size + 1),
        replace(out, sha256=OTHER_RID * 2),
    ):
        _assert_refused_or_unclean(
            lambda changed=changed: protocol.validate_parent_settlement(
                replace(context, descriptor_proofs=(changed, err))))


def test_worker_line_counts_are_bound_to_parent_computed_stage_proof(tmp_path):
    context = _clean_case(tmp_path, stdout=b"a\n")
    streams = list(context.settlement.streams)
    index = next(i for i, stream in enumerate(streams)
                 if stream.role is protocol.StreamRole.STDOUT)
    streams[index] = replace(streams[index], lines=0)
    changed = replace(context, settlement=replace(
        context.settlement, streams=tuple(streams)))
    _assert_refused_or_unclean(
        lambda: protocol.validate_parent_settlement(changed))


def test_parent_proofs_must_follow_the_same_canonical_role_order(tmp_path):
    context = _clean_case(tmp_path)
    with pytest.raises(protocol.ProtocolError, match="order"):
        protocol.validate_parent_settlement(
            replace(context, descriptor_proofs=tuple(reversed(context.descriptor_proofs))))


def test_requested_empty_sink_still_needs_empty_digest_and_claim(tmp_path):
    context = _clean_case(tmp_path, stdout=b"")

    def attempt():
        streams = list(context.settlement.streams)
        stdout_index = next(i for i, stream in enumerate(streams)
                            if stream.role is protocol.StreamRole.STDOUT)
        streams[stdout_index] = replace(streams[stdout_index], retained_sha256=None)
        settlement = replace(context.settlement, streams=tuple(streams))
        return protocol.validate_parent_settlement(
            replace(context, settlement=settlement))

    _assert_refused_or_unclean(attempt)


def test_unrequested_output_may_be_observed_but_never_retain_a_claim(tmp_path):
    invocation = _invocation(tmp_path, raw_path=None, stderr_path=None)
    streams = (
        _stream(protocol.StreamRole.STDIN, protocol.StreamTerminal.COMPLETE),
        _stream(protocol.StreamRole.STDOUT, protocol.StreamTerminal.EOF,
                observed=b"x", retained=b"x", claim_id=SYNTHETIC_CLAIM),
        _stream(protocol.StreamRole.STDERR, protocol.StreamTerminal.EOF),
    )
    settlement = _settlement(streams)
    proof = protocol.DescriptorProof(
        role=protocol.StreamRole.STDOUT, claim_id=SYNTHETIC_CLAIM,
        size=1, sha256=_digest(b"x"), lines=0,
    )
    context = protocol.ParentSettlementContext(
        request=invocation.worker, ready=_ready(), prepared=_prepared(),
        started=_started(),
        settlement=settlement, descriptor_proofs=(proof,),
        expected_worker_pid=WORKER_PID,
        expected_launcher_pid=TOOL_PID,
        expected_launcher_pgid=TOOL_PID,
        expected_containment_kind=protocol.ContainmentKind.CGROUP_V2,
        expected_containment_id=CGROUP_ID, worker_returncode=0,
        worker_reaped=True, control_eof=True, trailing_control_bytes=0,
        prepared_identity_verified=True, tool_identity_verified=True,
        containment_verified=True,
        containment_bound=True, containment_empty=True, stages_closed=True,
    )
    _assert_refused_or_unclean(lambda: protocol.validate_parent_settlement(context))


def test_data_stdin_count_and_digest_are_bound_to_the_request(tmp_path):
    context = _clean_case(tmp_path, stdin_data="abc")
    assert protocol.validate_parent_settlement(context).capture_complete is True
    streams = list(context.settlement.streams)
    stdin_index = next(i for i, stream in enumerate(streams)
                       if stream.role is protocol.StreamRole.STDIN)
    streams[stdin_index] = _stream(
        protocol.StreamRole.STDIN, protocol.StreamTerminal.COMPLETE,
        observed=b"ab")
    bad = replace(context, settlement=replace(context.settlement,
                                               streams=tuple(streams)))
    _assert_refused_or_unclean(lambda: protocol.validate_parent_settlement(bad))


def test_file_stdin_claim_proof_and_stream_are_bound_in_canonical_order(tmp_path):
    source = b"file-input\n"
    context = _clean_case(
        tmp_path,
        input_file=tmp_path / "input.bin",
        stdin_file_bytes=source,
    )
    assert tuple(claim.role for claim in context.request.descriptor_claims) == tuple(
        protocol.StreamRole
    )
    assert tuple(proof.role for proof in context.descriptor_proofs) == tuple(
        protocol.StreamRole
    )
    assert protocol.validate_parent_settlement(context).capture_complete is True

    stdin_proof = context.descriptor_proofs[0]
    bad_proofs = (replace(stdin_proof, sha256=_digest(b"different")),
                  *context.descriptor_proofs[1:])
    _assert_refused_or_unclean(
        lambda: protocol.validate_parent_settlement(
            replace(context, descriptor_proofs=bad_proofs)))


def test_null_stdin_cannot_claim_observed_input(tmp_path):
    context = _clean_case(tmp_path)
    streams = list(context.settlement.streams)
    stdin_index = next(i for i, stream in enumerate(streams)
                       if stream.role is protocol.StreamRole.STDIN)
    streams[stdin_index] = _stream(
        protocol.StreamRole.STDIN, protocol.StreamTerminal.COMPLETE,
        observed=b"x")
    bad = replace(context, settlement=replace(context.settlement,
                                               streams=tuple(streams)))
    _assert_refused_or_unclean(lambda: protocol.validate_parent_settlement(bad))


def test_peer_closed_stdin_is_settled_but_not_capture_complete(tmp_path):
    context = _clean_case(tmp_path, stdin_data="abc")
    streams = list(context.settlement.streams)
    stdin_index = next(i for i, stream in enumerate(streams)
                       if stream.role is protocol.StreamRole.STDIN)
    streams[stdin_index] = _stream(
        protocol.StreamRole.STDIN, protocol.StreamTerminal.PEER_CLOSED,
        observed=b"a", observed_digest=None)
    degraded = replace(context, settlement=replace(context.settlement,
                                                    streams=tuple(streams)))
    result = protocol.validate_parent_settlement(degraded)
    assert result.mechanically_settled is True
    assert result.capture_complete is False


def _capped_case(tmp_path, *, requested_cap, retained, observed=b"abcdef"):
    context = _clean_case(tmp_path, stdout=retained,
                          max_output_bytes=requested_cap)
    streams = list(context.settlement.streams)
    stdout_index = next(i for i, stream in enumerate(streams)
                        if stream.role is protocol.StreamRole.STDOUT)
    claim = _descriptor_claim(context.request, protocol.StreamRole.STDOUT)
    streams[stdout_index] = _stream(
        protocol.StreamRole.STDOUT, protocol.StreamTerminal.CAPPED,
        observed=observed, retained=retained, claim_id=claim.claim_id)
    context = replace(context, settlement=replace(context.settlement,
                                                   streams=tuple(streams)))
    return context


@pytest.mark.parametrize("cap,retained", [(3, b"ab"), (3, b"abcd")])
def test_capped_stage_must_equal_the_exact_requested_prefix_length(tmp_path, cap, retained):
    context = _capped_case(tmp_path, requested_cap=cap, retained=retained)
    _assert_refused_or_unclean(lambda: protocol.validate_parent_settlement(context))


@pytest.mark.parametrize("cap,retained", [(3, b"abc"), (0, b"")])
def test_exact_capped_prefix_is_authenticated_but_never_complete(tmp_path, cap, retained):
    context = _capped_case(tmp_path, requested_cap=cap, retained=retained)
    result = protocol.validate_parent_settlement(context)
    assert result.mechanically_settled is True
    assert result.capture_complete is False


def test_worker_cannot_invent_a_cap_that_the_parent_did_not_request(tmp_path):
    context = _clean_case(tmp_path, stdout=b"abc")
    streams = list(context.settlement.streams)
    stdout_index = next(i for i, stream in enumerate(streams)
                        if stream.role is protocol.StreamRole.STDOUT)
    claim = _descriptor_claim(context.request, protocol.StreamRole.STDOUT)
    streams[stdout_index] = _stream(
        protocol.StreamRole.STDOUT, protocol.StreamTerminal.CAPPED,
        observed=b"abcdef", retained=b"abc", claim_id=claim.claim_id)
    context = replace(context, settlement=replace(context.settlement,
                                                   streams=tuple(streams)))
    _assert_refused_or_unclean(lambda: protocol.validate_parent_settlement(context))


def test_eof_cannot_exceed_a_requested_cap_and_validate_complete(tmp_path):
    context = _clean_case(tmp_path, stdout=b"abcdef", max_output_bytes=3)
    _assert_refused_or_unclean(lambda: protocol.validate_parent_settlement(context))


def test_eof_cannot_hide_requested_bytes_that_never_reached_the_stage(tmp_path):
    context = _clean_case(tmp_path, stdout=b"abc")
    streams = list(context.settlement.streams)
    stdout_index = next(i for i, stream in enumerate(streams)
                        if stream.role is protocol.StreamRole.STDOUT)
    claim = _descriptor_claim(context.request, protocol.StreamRole.STDOUT)
    streams[stdout_index] = _stream(
        protocol.StreamRole.STDOUT, protocol.StreamTerminal.EOF,
        observed=b"abcdef", retained=b"abc", claim_id=claim.claim_id)
    degraded = replace(context, settlement=replace(context.settlement,
                                                    streams=tuple(streams)))
    _assert_refused_or_unclean(
        lambda: protocol.validate_parent_settlement(degraded))


def test_sink_error_can_authenticate_a_prefix_but_never_be_clean(tmp_path):
    context = _clean_case(tmp_path, stdout=b"abc")
    streams = list(context.settlement.streams)
    stdout_index = next(i for i, stream in enumerate(streams)
                        if stream.role is protocol.StreamRole.STDOUT)
    claim = _descriptor_claim(context.request, protocol.StreamRole.STDOUT)
    streams[stdout_index] = _stream(
        protocol.StreamRole.STDOUT, protocol.StreamTerminal.SINK_ERROR,
        observed=b"abcdef", retained=b"abc", claim_id=claim.claim_id)
    degraded = replace(context, settlement=replace(context.settlement,
                                                    streams=tuple(streams)))
    result = protocol.validate_parent_settlement(degraded)
    assert result.mechanically_settled is True
    assert result.capture_complete is False


@pytest.mark.parametrize("terminal", [
    protocol.ExecutionTerminal.TIMED_OUT,
    protocol.ExecutionTerminal.CANCELLED,
    protocol.ExecutionTerminal.WORKER_FAILED,
])
def test_noncomplete_execution_terminal_cannot_be_laundered_by_clean_streams(tmp_path,
                                                                            terminal):
    context = _clean_case(tmp_path)
    degraded = replace(
        context,
        settlement=replace(context.settlement, terminal=terminal),
    )
    _assert_refused_or_unclean(
        lambda: protocol.validate_parent_settlement(degraded))


# -- PGID containment is bounded fallback, never proof of the entire tree -------


def test_pgid_fallback_cannot_launder_worker_tree_testimony_into_clean(tmp_path):
    context = _clean_case(tmp_path,
                          containment_kind=protocol.ContainmentKind.PGID)
    result = protocol.validate_parent_settlement(context)
    assert result.tree_proven is False
    assert result.capture_complete is False


def test_cgroup_truth_requires_independent_binding_and_empty_membership(tmp_path):
    context = _clean_case(tmp_path)
    assert protocol.validate_parent_settlement(context).tree_proven is True
    for field in ("tool_identity_verified", "containment_verified",
                  "containment_bound", "containment_empty"):
        _assert_refused_or_unclean(
            lambda field=field: protocol.validate_parent_settlement(
                replace(context, **{field: False})))


def test_parent_context_repr_does_not_disclose_request_credentials(tmp_path):
    context = _clean_case(tmp_path)
    assert "never-render-this" not in repr(context)
    assert "QUARRY_TEST_SECRET" not in repr(context)
