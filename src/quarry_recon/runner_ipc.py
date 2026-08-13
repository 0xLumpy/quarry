"""Bounded stdlib-only framing primitives for the runner process boundary.

This module deliberately knows nothing about Quarry protocol models, subprocesses,
filesystem stages, or containment.  Its errors contain only fixed reason labels and
never include channel bytes, descriptor numbers, or rejected length values.
"""
from __future__ import annotations

import os
import struct


_ERROR_CODES = frozenset({
    "decoder_finished",
    "input_chunk_exceeds_limit",
    "invalid_descriptor",
    "invalid_frame_length",
    "invalid_limit",
    "invalid_payload",
    "read_failed",
    "trailing_bytes",
    "truncated_frame",
    "unexpected_eof",
    "write_failed",
})


class IpcError(RuntimeError):
    """A fixed, value-free failure at the private framing boundary."""

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in _ERROR_CODES:
            raise TypeError("invalid runner IPC error code")
        self.code = code
        super().__init__(f"runner_ipc:{code}")


def _validate_fd(fd: int) -> int:
    if type(fd) is not int or fd < 0:
        raise IpcError("invalid_descriptor")
    return fd


def _validate_limit(max_frame_bytes: int) -> int:
    if (type(max_frame_bytes) is not int
            or not 1 <= max_frame_bytes <= (1 << 31) - 1):
        raise IpcError("invalid_limit")
    return max_frame_bytes


def _read_exact(fd: int, size: int, *, initial: bool = False) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = os.read(fd, remaining)
        except InterruptedError:
            continue
        except OSError:
            raise IpcError("read_failed") from None
        if not chunk:
            if initial and remaining == size:
                raise IpcError("unexpected_eof")
            raise IpcError("truncated_frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(fd: int, *, max_frame_bytes: int) -> bytes:
    """Read exactly one length-prefixed frame from a blocking descriptor."""
    fd = _validate_fd(fd)
    limit = _validate_limit(max_frame_bytes)
    header = _read_exact(fd, 4, initial=True)
    declared = struct.unpack(">I", header)[0]
    if declared == 0 or declared > limit:
        raise IpcError("invalid_frame_length")
    return header + _read_exact(fd, declared)


def read_payload(fd: int, size: int, *, max_payload_bytes: int) -> bytes:
    """Read one exact bounded raw segment between framed protocol records."""
    fd = _validate_fd(fd)
    limit = _validate_limit(max_payload_bytes)
    if type(size) is not int or not 0 <= size <= limit:
        raise IpcError("invalid_limit")
    return _read_exact(fd, size)


def require_eof(fd: int) -> None:
    """Require the peer to close without even one trailing channel byte."""
    fd = _validate_fd(fd)
    while True:
        try:
            chunk = os.read(fd, 1)
        except InterruptedError:
            continue
        except OSError:
            raise IpcError("read_failed") from None
        if chunk:
            raise IpcError("trailing_bytes")
        return


def write_all(fd: int, data: bytes) -> None:
    """Write one already-bounded payload completely to a blocking descriptor."""
    fd = _validate_fd(fd)
    if type(data) is not bytes:
        raise IpcError("invalid_payload")
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(fd, view[offset:])
        except InterruptedError:
            continue
        except OSError:
            raise IpcError("write_failed") from None
        if written <= 0:
            raise IpcError("write_failed")
        offset += written


class IncrementalFrameDecoder:
    """Incrementally split a bounded byte stream into exact protocol frames."""

    __slots__ = ("_buffer", "_finished", "_max_frame_bytes")

    def __init__(self, max_frame_bytes: int) -> None:
        self._max_frame_bytes = _validate_limit(max_frame_bytes)
        self._buffer = bytearray()
        self._finished = False

    @property
    def pending_size(self) -> int:
        return len(self._buffer)

    def feed(self, data: bytes) -> tuple[bytes, ...]:
        if self._finished:
            raise IpcError("decoder_finished")
        if type(data) is not bytes:
            raise IpcError("invalid_payload")
        # Supervisor reads use a much smaller fixed chunk.  This independent cap
        # prevents a direct caller from forcing an arbitrarily large temporary
        # concatenation before the declared frame length can be inspected.
        if len(data) > self._max_frame_bytes + 4:
            raise IpcError("input_chunk_exceeds_limit")
        self._buffer.extend(data)
        frames: list[bytes] = []
        consumed = 0
        total = len(self._buffer)
        while total - consumed >= 4:
            declared = struct.unpack(">I", self._buffer[consumed:consumed + 4])[0]
            if declared == 0 or declared > self._max_frame_bytes:
                if consumed:
                    del self._buffer[:consumed]
                raise IpcError("invalid_frame_length")
            frame_size = declared + 4
            if total - consumed < frame_size:
                break
            frames.append(bytes(self._buffer[consumed:consumed + frame_size]))
            consumed += frame_size
        if consumed:
            del self._buffer[:consumed]
        # Once complete frames are removed, the retained suffix can be at most one
        # declared frame.  Reject a programming/invariant breach fail-closed.
        if len(self._buffer) > self._max_frame_bytes + 4:
            raise IpcError("input_chunk_exceeds_limit")
        return tuple(frames)

    def finish(self) -> None:
        if self._finished:
            raise IpcError("decoder_finished")
        self._finished = True
        if self._buffer:
            raise IpcError("truncated_frame")
