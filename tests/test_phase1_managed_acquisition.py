"""Focused Phase 1 gates for repository-owned HTTP acquisition."""
from __future__ import annotations

import hashlib
import io
import os

import pytest

from quarry_recon import contract


pytestmark = pytest.mark.offline


class _CancellingResponse:
    def __init__(self, cancellation):
        self._reads = 0
        self._cancellation = cancellation

    def read(self, _size=-1):
        self._reads += 1
        if self._reads == 1:
            return b"known-prefix"
        raise self._cancellation


def test_stream_to_fd_keeps_exact_binary_body_and_digest(tmp_path):
    path = tmp_path / "private-stage"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        body = b"\x00managed\xffbody\n"
        size, digest = contract.stream_to_fd(
            io.BytesIO(body), fd, budget_path=tmp_path,
            chunk=3, governor=contract.DiskGovernor(reserve_bytes=0),
        )
    finally:
        os.close(fd)

    assert (size, digest) == (len(body), hashlib.sha256(body).hexdigest())
    assert path.read_bytes() == body


def test_stream_to_fd_mirrors_one_response_into_two_private_stages(tmp_path):
    primary_path = tmp_path / "partial-stage"
    mirror_path = tmp_path / "complete-stage"
    primary = os.open(primary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    mirror = os.open(mirror_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    body = b"one response, two unpublished claims\x00\xff"
    try:
        size, digest = contract.stream_to_fd(
            io.BytesIO(body), primary, mirror_fd=mirror, budget_path=tmp_path,
            chunk=5, governor=contract.DiskGovernor(reserve_bytes=0),
        )
    finally:
        os.close(mirror)
        os.close(primary)

    assert (size, digest) == (len(body), hashlib.sha256(body).hexdigest())
    assert primary_path.read_bytes() == mirror_path.read_bytes() == body


@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit])
def test_stream_to_fd_attaches_exact_prefix_to_cancellation(tmp_path, kind):
    path = tmp_path / "cancelled-stage"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    cancellation = kind("cancel managed response")
    try:
        with pytest.raises(kind) as caught:
            contract.stream_to_fd(
                _CancellingResponse(cancellation), fd, budget_path=tmp_path,
                chunk=64, governor=contract.DiskGovernor(reserve_bytes=0),
            )
    finally:
        os.close(fd)

    assert caught.value is cancellation
    assert cancellation.bytes_written == len(b"known-prefix")
    assert cancellation.sha256 == hashlib.sha256(b"known-prefix").hexdigest()
    assert path.read_bytes() == b"known-prefix"
