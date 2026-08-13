"""Pure protocol checks for the fixed Phase-1 worker bootstrap."""
from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import FrozenInstanceError, replace

import pytest

from quarry_recon import runner_protocol as protocol


pytestmark = pytest.mark.offline

RID = "61" * 16
WORKER_PID = 41001
DIGEST = "a4" * 32
EMPTY = hashlib.sha256(b"").hexdigest()


def _frame(kind: str, body: dict) -> bytes:
    payload = json.dumps(
        {"version": protocol.PROTOCOL_VERSION, "kind": kind, "body": body},
        separators=(",", ":"),
    ).encode("utf-8")
    return struct.pack(">I", len(payload)) + payload


def _command(kind=protocol.WorkerCommandKind.ABORT, **overrides):
    values = {
        "request_id": RID,
        "request_sha256": DIGEST,
        "worker_pid": WORKER_PID,
        "command": kind,
    }
    values.update(overrides)
    return protocol.WorkerCommand(**values)


def _not_started_settlement(*, detail="parent_abort"):
    streams = tuple(
        protocol.StreamSettlement(
            role=role,
            terminal=protocol.StreamTerminal.NOT_STARTED,
            observed_bytes=0,
            retained_bytes=0,
            observed_sha256=None,
            retained_sha256=None,
        )
        for role in protocol.StreamRole
    )
    return protocol.WorkerSettlement(
        request_id=RID,
        terminal=protocol.ExecutionTerminal.CANCELLED,
        launched=False,
        exit_code=None,
        process_group_settled=False,
        process_tree_settled=False,
        streams=streams,
        worker_pid=WORKER_PID,
        tool_pid=None,
        detail=detail,
    )


@pytest.mark.parametrize("kind", tuple(protocol.WorkerCommandKind))
def test_worker_command_is_frozen_request_digest_and_worker_bound(kind):
    command = _command(kind)
    with pytest.raises(FrozenInstanceError):
        command.request_id = "62" * 16

    frame = protocol.encode_command(command)
    assert protocol.decode_command(frame) == command
    assert protocol.encode_command(protocol.decode_command(frame)) == frame
    rendered = repr(command)
    assert kind.value in rendered
    assert RID not in rendered and DIGEST not in rendered
    assert str(WORKER_PID) not in rendered


def test_ready_only_command_preserves_the_legacy_four_field_wire_schema():
    command = _command()
    frame = protocol.encode_command(command)
    envelope = json.loads(frame[4:])

    assert set(envelope["body"]) == {
        "request_id", "request_sha256", "worker_pid", "command",
    }
    assert protocol.decode_command(_frame("launch_command", command.to_dict())) == command

    explicit_null = command.to_dict()
    explicit_null["prepared_sha256"] = None
    assert protocol.decode_command(_frame("launch_command", explicit_null)) == command


@pytest.mark.parametrize("field,value", [
    ("request_id", "62" * 16),
    ("request_sha256", "b5" * 32),
    ("worker_pid", WORKER_PID + 1),
])
def test_command_correlation_changes_remain_explicit_wire_facts(field, value):
    original = _command()
    changed = replace(original, **{field: value})
    assert protocol.decode_command(protocol.encode_command(changed)) == changed
    assert protocol.encode_command(changed) != protocol.encode_command(original)


@pytest.mark.parametrize("mutation", [
    lambda body: body.pop("request_sha256"),
    lambda body: body.__setitem__("extra", True),
    lambda body: body.__setitem__("command", "continue"),
    lambda body: body.__setitem__("command", True),
    lambda body: body.__setitem__("worker_pid", True),
    lambda body: body.__setitem__("request_sha256", "A" * 64),
])
def test_command_wire_schema_fails_closed_without_rendering_private_values(mutation):
    body = _command().to_dict()
    body["private-value"] = "never-render-this"
    body.pop("private-value")
    mutation(body)
    with pytest.raises(protocol.ProtocolError) as error:
        protocol.decode_command(_frame("launch_command", body))
    assert "never-render-this" not in str(error.value)
    assert DIGEST not in str(error.value)


def test_parent_abort_has_an_unambiguous_terminal_negative_transcript():
    ready = protocol.ReadyFrame(RID, WORKER_PID, DIGEST)
    settlement = _not_started_settlement()
    transcript = protocol.validate_control_sequence((ready, settlement))
    assert transcript.ready == ready
    assert transcript.prepared is None and transcript.started is None
    assert transcript.settlement.terminal is protocol.ExecutionTerminal.CANCELLED
    assert transcript.settlement.launched is False
    assert all(
        stream.terminal is protocol.StreamTerminal.NOT_STARTED
        for stream in transcript.settlement.streams
    )
    assert protocol.decode_settlement(protocol.encode_settlement(settlement)) == settlement


def test_control_dispatch_accepts_only_worker_to_parent_records():
    ready = protocol.ReadyFrame(RID, WORKER_PID, DIGEST)
    settlement = _not_started_settlement()
    assert protocol.decode_control_frame(protocol.encode_ready(ready)) == ready
    assert protocol.decode_control_frame(protocol.encode_settlement(settlement)) == settlement
    with pytest.raises(protocol.ProtocolError, match="control frame"):
        protocol.decode_control_frame(protocol.encode_command(_command()))


def test_control_dispatch_parses_the_envelope_once(monkeypatch):
    ready = protocol.ReadyFrame(RID, WORKER_PID, DIGEST)
    calls = []
    original = protocol.json.loads

    def counted(*args, **kwargs):
        calls.append(None)
        return original(*args, **kwargs)

    monkeypatch.setattr(protocol.json, "loads", counted)
    assert protocol.decode_control_frame(protocol.encode_ready(ready)) == ready
    assert calls == [None]


def test_not_started_stream_cannot_smuggle_activity_into_abort_settlement():
    settlement = _not_started_settlement()
    stream = next(
        record for record in settlement.streams
        if record.role is protocol.StreamRole.STDOUT
    )
    with pytest.raises(protocol.ProtocolError, match="unstarted stream"):
        replace(stream, observed_bytes=1, observed_sha256=EMPTY)
