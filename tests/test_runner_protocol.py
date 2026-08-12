"""Pure Phase-1 runner request and settlement protocol checks."""
from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import FrozenInstanceError, replace

import pytest

from quarry_recon import runner_protocol as protocol

pytestmark = pytest.mark.offline

RID = "01" * 16
EMPTY = hashlib.sha256(b"").hexdigest()


def _request(**overrides):
    values = {
        "request_id": RID,
        "tool": "fixture",
        "cmd": ["/usr/bin/printf", "%s", "evidence"],
        "timeout": 30,
        "stdin_data": None,
        "input_file": None,
        "ok_empty": True,
        "ok_codes": (0,),
        "env": {"TOKEN": "private-value", "Z": "last"},
        "base_environment": {"PATH": "/usr/bin", "TOKEN": "old-value"},
        "cwd": "/tmp",
        "raw_path": "/tmp/stdout",
        "stderr_path": "/tmp/stderr",
        "max_output_bytes": None,
    }
    values.update(overrides)
    return protocol.normalize_invocation(**values)


def _stream(role, terminal, *, observed=0, retained=0, observed_digest=EMPTY,
            retained_digest=None, claim_id=None, lines=0, detail=None):
    return protocol.StreamSettlement(
        role=role, terminal=terminal, observed_bytes=observed,
        retained_bytes=retained, observed_sha256=observed_digest,
        retained_sha256=retained_digest, claim_id=claim_id,
        lines=lines, detail=detail,
    )


def _streams(*, stdout_terminal=protocol.StreamTerminal.EOF):
    return (
        _stream(protocol.StreamRole.STDIN, protocol.StreamTerminal.COMPLETE),
        _stream(protocol.StreamRole.STDOUT, stdout_terminal),
        _stream(protocol.StreamRole.STDERR, protocol.StreamTerminal.EOF),
    )


def _settlement(**overrides):
    values = {
        "request_id": RID,
        "terminal": protocol.ExecutionTerminal.COMPLETE,
        "launched": True,
        "exit_code": 0,
        "process_group_settled": True,
        "process_tree_settled": True,
        "streams": _streams(),
        "worker_pid": 100,
        "tool_pid": 101,
        "detail": None,
    }
    values.update(overrides)
    return protocol.WorkerSettlement(**values)


def _frame(doc):
    payload = json.dumps(doc, separators=(",", ":")).encode()
    return struct.pack(">I", len(payload)) + payload


def test_request_normalization_is_deterministic_and_payload_is_out_of_band(tmp_path):
    invocation = _request(
        stdin_data="héllo",
        raw_path=tmp_path / "out",
        stderr_path=tmp_path / "err",
        cwd=tmp_path,
    )
    request = invocation.worker
    assert request.stdin_mode is protocol.StdinMode.DATA
    assert request.stdin_bytes == len("héllo".encode())
    assert request.stdin_sha256 == hashlib.sha256("héllo".encode()).hexdigest()
    assert invocation.stdin_data == "héllo".encode()
    assert request.environment == (("PATH", "/usr/bin"), ("TOKEN", "private-value"), ("Z", "last"))
    assert request.cwd == str(tmp_path.resolve())
    assert invocation.raw_path == str((tmp_path / "out").resolve())
    assert "stdin_data" not in request.to_dict()


def test_request_and_invocation_reprs_never_disclose_argv_environment_or_stdin():
    invocation = _request(stdin_data="stdin-secret", cmd=["tool", "argv-secret"],
                          env={"API_KEY": "environment-secret"})
    rendered = repr(invocation) + repr(invocation.worker)
    for secret in ("stdin-secret", "argv-secret", "environment-secret", "API_KEY"):
        assert secret not in rendered


@pytest.mark.parametrize("field,value", [
    ("tool", ""), ("tool", "bad\x00tool"), ("tool", object()),
    ("cmd", []), ("cmd", "true"), ("cmd", ["true", 1]),
    ("timeout", -1), ("timeout", True), ("timeout", math.inf), ("timeout", math.nan),
    ("ok_empty", 1), ("ok_codes", []), ("ok_codes", (0, 0)),
    ("ok_codes", (True,)), ("env", [("A", "B")]),
    ("max_output_bytes", True), ("max_output_bytes", -1),
])
def test_invalid_request_fields_fail_without_echoing_rejected_values(field, value):
    with pytest.raises(protocol.ProtocolError) as error:
        _request(**{field: value})
    assert repr(value) not in str(error.value)


@pytest.mark.parametrize("env", [
    {"": "x"}, {"BAD=KEY": "x"}, {"NUL": "x\x00y"}, {1: "x"}, {"K": object()},
])
def test_invalid_environment_is_rejected_without_disclosure(env):
    with pytest.raises(protocol.ProtocolError) as error:
        _request(env=env)
    assert "object at" not in str(error.value) and "x\x00y" not in str(error.value)


def test_effective_base_environment_must_be_explicitly_captured():
    with pytest.raises(protocol.ProtocolError, match="base_environment"):
        _request(base_environment=None)


def test_stdin_sources_and_path_aliases_fail_closed(tmp_path):
    same = tmp_path / "same"
    with pytest.raises(protocol.ProtocolError, match="multiple stdin sources"):
        _request(stdin_data="x", input_file=tmp_path / "input")
    with pytest.raises(protocol.ProtocolError, match="path claims alias"):
        _request(raw_path=same, stderr_path=same)
    with pytest.raises(protocol.ProtocolError, match="path claims alias"):
        _request(input_file=same, raw_path=same)
    with pytest.raises(protocol.ProtocolError, match="output cap requires stdout"):
        _request(raw_path=None, max_output_bytes=0)


def test_empty_stdin_data_is_distinct_from_devnull():
    data = _request(stdin_data="")
    null = _request(stdin_data=None)
    assert data.worker.stdin_mode is protocol.StdinMode.DATA
    assert data.worker.stdin_bytes == 0 and data.worker.stdin_sha256 == EMPTY
    assert null.worker.stdin_mode is protocol.StdinMode.NULL


def test_stdin_data_preserves_nul_and_rejects_unpaired_surrogates():
    invocation = _request(stdin_data="a\x00b")
    assert invocation.stdin_data == b"a\x00b"
    assert invocation.worker.stdin_bytes == 3
    assert invocation.worker.stdin_sha256 == hashlib.sha256(b"a\x00b").hexdigest()
    with pytest.raises(protocol.ProtocolError, match="unicode"):
        _request(stdin_data="a\ud800b")


def test_request_is_frozen_and_control_frame_round_trips_canonically():
    request = _request().worker
    with pytest.raises(FrozenInstanceError):
        request.tool = "changed"
    frame = protocol.encode_request(request)
    assert protocol.decode_request(frame) == request
    assert protocol.encode_request(protocol.decode_request(frame)) == frame
    assert len(frame) == struct.unpack(">I", frame[:4])[0] + 4


def test_request_frame_contains_private_control_data_but_errors_do_not():
    request = _request(env={"API_KEY": "private-value"}).worker
    frame = protocol.encode_request(request)
    assert b"private-value" in frame
    damaged = frame[:-1]
    with pytest.raises(protocol.ProtocolError) as error:
        protocol.decode_request(damaged)
    assert "private-value" not in str(error.value)


@pytest.mark.parametrize("frame,match", [
    (b"", "truncated"),
    (struct.pack(">I", 0), "length"),
    (struct.pack(">I", protocol.MAX_FRAME_BYTES + 1), "length"),
    (struct.pack(">I", 5) + b"{}", "length mismatch"),
    (struct.pack(">I", 2) + b"\xff\xff", "invalid JSON"),
])
def test_malformed_and_oversized_frames_fail_closed(frame, match):
    with pytest.raises(protocol.ProtocolError, match=match):
        protocol.decode_request(frame)


def test_duplicate_unknown_missing_kind_and_version_fields_fail_closed():
    request = _request().worker.to_dict()
    duplicate = ('{"version":1,"kind":"request","kind":"request","body":'
                 + json.dumps(request, separators=(",", ":")) + "}").encode()
    with pytest.raises(protocol.ProtocolError, match="duplicate JSON key"):
        protocol.decode_request(struct.pack(">I", len(duplicate)) + duplicate)
    for doc in (
        {"version": 2, "kind": "request", "body": request},
        {"version": 1, "kind": "settlement", "body": request},
        {"version": 1, "kind": "request", "body": request, "extra": 1},
        {"version": 1, "kind": "request"},
    ):
        with pytest.raises(protocol.ProtocolError):
            protocol.decode_request(_frame(doc))


def test_unknown_or_missing_request_body_fields_are_rejected():
    body = _request().worker.to_dict()
    with pytest.raises(protocol.ProtocolError, match="keys"):
        protocol.decode_request(_frame({"version": 1, "kind": "request",
                                        "body": dict(body, surprise=True)}))
    missing = dict(body)
    missing.pop("timeout")
    with pytest.raises(protocol.ProtocolError, match="keys"):
        protocol.decode_request(_frame({"version": 1, "kind": "request", "body": missing}))


def test_direct_request_decoder_rejects_non_string_environment_keys_typed():
    body = _request().worker.to_dict()
    body["environment"] = {1: "not-json-but-valid-direct-input"}
    with pytest.raises(protocol.ProtocolError, match="environment.key"):
        protocol.WorkerRequest.from_dict(body)


def test_deep_and_node_heavy_json_are_rejected_before_model_construction():
    deep = value = {}
    for _ in range(protocol.MAX_JSON_DEPTH + 2):
        value["x"] = {}
        value = value["x"]
    with pytest.raises(protocol.ProtocolError, match="depth"):
        protocol.decode_request(_frame({"version": 1, "kind": "request", "body": deep}))
    heavy = [None] * protocol.MAX_JSON_NODES
    with pytest.raises(protocol.ProtocolError, match="node"):
        protocol.decode_request(_frame({"version": 1, "kind": "request", "body": {"x": heavy}}))


def test_worker_settlement_round_trips_but_cannot_claim_parent_cleanliness():
    settlement = _settlement()
    assert not hasattr(settlement, "mechanically_settled")
    assert not hasattr(settlement, "capture_complete")
    frame = protocol.encode_settlement(settlement)
    assert protocol.decode_settlement(frame) == settlement
    assert protocol.encode_settlement(protocol.decode_settlement(frame)) == frame


def test_process_completion_is_not_capture_completion_when_stdout_is_capped():
    prefix = hashlib.sha256(b"abc").hexdigest()
    whole = hashlib.sha256(b"abcdef").hexdigest()
    streams = (
        _stream(protocol.StreamRole.STDIN, protocol.StreamTerminal.COMPLETE),
        _stream(protocol.StreamRole.STDOUT, protocol.StreamTerminal.CAPPED,
                observed=6, retained=3, observed_digest=whole, retained_digest=prefix,
                claim_id="03" * 16),
        _stream(protocol.StreamRole.STDERR, protocol.StreamTerminal.EOF),
    )
    settlement = _settlement(streams=streams)
    assert settlement.terminal is protocol.ExecutionTerminal.COMPLETE
    assert not hasattr(settlement, "capture_complete")


@pytest.mark.parametrize("changes", [
    {"exit_code": None},
    {"tool_pid": None},
])
def test_complete_worker_record_requires_launch_identity_and_exit(changes):
    with pytest.raises(protocol.ProtocolError):
        _settlement(**changes)


def test_worker_process_settlement_flags_are_testimony_not_parent_truth():
    settlement = _settlement(process_group_settled=False, process_tree_settled=False)
    assert settlement.process_group_settled is False
    assert settlement.process_tree_settled is False
    assert not hasattr(settlement, "mechanically_settled")


def test_unlaunched_settlement_has_no_tool_pid_or_exit_code():
    settlement = _settlement(
        terminal=protocol.ExecutionTerminal.LAUNCH_FAILED,
        launched=False, exit_code=None, tool_pid=None,
        streams=tuple(
            _stream(role, protocol.StreamTerminal.WORKER_CRASH,
                    observed_digest=None)
            for role in protocol.StreamRole
        ),
    )
    assert settlement.launched is False
    assert not hasattr(settlement, "capture_complete")


def test_stream_roles_must_be_exact_and_unique():
    streams = list(_streams())
    streams[2] = streams[1]
    with pytest.raises(protocol.ProtocolError, match="roles"):
        _settlement(streams=tuple(streams))


@pytest.mark.parametrize("stream", [
    lambda: _stream(protocol.StreamRole.STDOUT, protocol.StreamTerminal.EOF,
                    observed=0, observed_digest="0" * 64),
    lambda: _stream(protocol.StreamRole.STDOUT, protocol.StreamTerminal.EOF,
                    observed=1, retained=2,
                    observed_digest=hashlib.sha256(b"x").hexdigest(),
                    retained_digest=hashlib.sha256(b"xx").hexdigest()),
    lambda: _stream(protocol.StreamRole.STDOUT, protocol.StreamTerminal.CAPPED,
                    observed=3, retained=3,
                    observed_digest=hashlib.sha256(b"abc").hexdigest(),
                    retained_digest=hashlib.sha256(b"abc").hexdigest()),
    lambda: _stream(protocol.StreamRole.STDIN, protocol.StreamTerminal.SINK_ERROR,
                    observed_digest=None),
])
def test_stream_counter_digest_and_terminal_contradictions_are_rejected(stream):
    with pytest.raises(protocol.ProtocolError):
        stream()


def test_unknown_settlement_fields_and_terminal_values_fail_closed():
    body = _settlement().to_dict()
    body["terminal"] = "clean-ish"
    with pytest.raises(protocol.ProtocolError, match="unknown enum"):
        protocol.decode_settlement(_frame({"version": 1, "kind": "settlement", "body": body}))
    body = _settlement().to_dict()
    body["streams"][0]["extra"] = True
    with pytest.raises(protocol.ProtocolError, match="keys"):
        protocol.decode_settlement(_frame({"version": 1, "kind": "settlement", "body": body}))


def test_settlement_detail_is_bounded_and_not_rendered():
    settlement = _settlement(detail="target-evidence-is-private")
    assert "target-evidence-is-private" not in repr(settlement)
    with pytest.raises(protocol.ProtocolError, match="limit"):
        replace(settlement, detail="x" * (protocol.MAX_DETAIL_BYTES + 1))
