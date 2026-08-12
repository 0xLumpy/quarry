"""Bounded byte-transport checks for the Phase-1 worker bootstrap."""
from __future__ import annotations

import os
import struct

import pytest

from quarry_recon import runner_ipc


pytestmark = pytest.mark.offline


def _wire(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def test_incremental_decoder_accepts_fragmented_and_multiple_frames():
    first = _wire(b"first")
    second = _wire(b"second")
    decoder = runner_ipc.IncrementalFrameDecoder(32)

    assert decoder.feed(first[:2]) == ()
    assert decoder.pending_size == 2
    assert decoder.feed(first[2:] + second) == (first, second)
    assert decoder.pending_size == 0
    decoder.finish()


@pytest.mark.parametrize("wire,code", [
    (struct.pack(">I", 0), "invalid_frame_length"),
    (struct.pack(">I", 33), "invalid_frame_length"),
    (_wire(b"incomplete")[:-1], "truncated_frame"),
])
def test_incremental_decoder_fails_closed_on_bad_or_incomplete_input(wire, code):
    decoder = runner_ipc.IncrementalFrameDecoder(32)
    if code == "truncated_frame":
        assert decoder.feed(wire) == ()
        with pytest.raises(runner_ipc.IpcError) as error:
            decoder.finish()
    else:
        with pytest.raises(runner_ipc.IpcError) as error:
            decoder.feed(wire)
    assert error.value.code == code


def test_incremental_decoder_is_terminal_after_finish():
    decoder = runner_ipc.IncrementalFrameDecoder(16)
    decoder.finish()
    with pytest.raises(runner_ipc.IpcError) as error:
        decoder.feed(b"")
    assert error.value.code == "decoder_finished"
    with pytest.raises(runner_ipc.IpcError) as error:
        decoder.finish()
    assert error.value.code == "decoder_finished"


def test_incremental_decoder_rejects_one_oversized_input_chunk_before_retaining_it():
    decoder = runner_ipc.IncrementalFrameDecoder(8)
    with pytest.raises(runner_ipc.IpcError) as error:
        decoder.feed(b"x" * 13)
    assert error.value.code == "input_chunk_exceeds_limit"
    assert decoder.pending_size == 0


def test_blocking_frame_reader_and_eof_contract_use_exact_channel_bytes():
    read_fd, write_fd = os.pipe()
    frame = _wire(b"private-frame")
    try:
        runner_ipc.write_all(write_fd, frame)
        os.close(write_fd)
        write_fd = -1
        assert runner_ipc.read_frame(read_fd, max_frame_bytes=64) == frame
        runner_ipc.require_eof(read_fd)
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def test_require_eof_rejects_even_one_trailing_byte():
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"x")
        os.close(write_fd)
        write_fd = -1
        with pytest.raises(runner_ipc.IpcError) as error:
            runner_ipc.require_eof(read_fd)
        assert error.value.code == "trailing_bytes"
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


@pytest.mark.parametrize("content,code", [
    (b"", "unexpected_eof"),
    (b"\x00\x00", "truncated_frame"),
    (struct.pack(">I", 0), "invalid_frame_length"),
    (struct.pack(">I", 65), "invalid_frame_length"),
    (struct.pack(">I", 4) + b"xx", "truncated_frame"),
])
def test_blocking_reader_classifies_eof_and_length_failures(content, code):
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, content)
        os.close(write_fd)
        write_fd = -1
        with pytest.raises(runner_ipc.IpcError) as error:
            runner_ipc.read_frame(read_fd, max_frame_bytes=64)
        assert error.value.code == code
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


@pytest.mark.parametrize("call", [
    lambda: runner_ipc.read_frame(-1, max_frame_bytes=8),
    lambda: runner_ipc.read_frame(0, max_frame_bytes=True),
    lambda: runner_ipc.write_all(-1, b"secret-channel-value"),
    lambda: runner_ipc.write_all(0, "secret-channel-value"),
    lambda: runner_ipc.IncrementalFrameDecoder(0),
])
def test_ipc_errors_are_typed_and_value_free(call):
    with pytest.raises(runner_ipc.IpcError) as error:
        call()
    rendered = str(error.value)
    assert rendered.startswith("runner_ipc:")
    assert "secret-channel-value" not in rendered
    assert "-1" not in rendered


def test_write_all_retries_interrupts_and_short_writes(monkeypatch):
    accepted = bytearray()
    calls = ["interrupt", 2, 1]

    def fake_write(fd, data):
        action = calls.pop(0) if calls else len(data)
        if action == "interrupt":
            raise InterruptedError
        accepted.extend(bytes(data[:action]))
        return action

    monkeypatch.setattr(runner_ipc.os, "write", fake_write)
    runner_ipc.write_all(7, b"abcdef")
    assert accepted == b"abcdef"
