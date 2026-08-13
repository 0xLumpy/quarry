"""Focused Phase 1 gates for repository-owned HTTP acquisition."""
from __future__ import annotations

import hashlib
import inspect
import io
import os
import sys
import threading

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


def test_stream_to_fd_accepts_an_authenticated_passive_shared_alias(tmp_path):
    path = tmp_path / "private-stage"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    passive_alias = os.dup(fd)
    body = b"passive aliases never mutate the shared file description"
    try:
        result = contract.stream_to_fd(
            io.BytesIO(body), fd, budget_path=tmp_path, chunk=7,
            governor=contract.DiskGovernor(reserve_bytes=0),
        )
    finally:
        os.close(passive_alias)
        os.close(fd)

    assert result == (len(body), hashlib.sha256(body).hexdigest())
    assert path.read_bytes() == body
    assert "no shared-open-file-description alias may write" in (
        contract.stream_to_fd.__doc__
    )


class _CountingResponse(io.BytesIO):
    def __init__(self, body=b"body"):
        super().__init__(body)
        self.reads = 0

    def read(self, size=-1):
        self.reads += 1
        return super().read(size)


def test_stream_to_fd_refuses_mirror_before_reading_or_writing(tmp_path):
    primary_path = tmp_path / "partial-stage"
    mirror_path = tmp_path / "complete-stage"
    primary = os.open(primary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    mirror = os.open(mirror_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    response = _CountingResponse()
    try:
        with pytest.raises(ValueError, match="mirror writes are not supported"):
            contract.stream_to_fd(
                response, primary, mirror_fd=mirror, budget_path=tmp_path,
                chunk=5, governor=contract.DiskGovernor(reserve_bytes=0),
            )
    finally:
        os.close(mirror)
        os.close(primary)

    assert response.reads == 0
    assert primary_path.read_bytes() == mirror_path.read_bytes() == b""


@pytest.mark.parametrize("chunk", [0, -1, True, 1.5, "1"])
@pytest.mark.parametrize("deadline", [0.0, 1.0])
def test_stream_to_fd_rejects_invalid_chunk_before_read(tmp_path, chunk, deadline):
    path = tmp_path / "preflight-stage"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    response = _CountingResponse()
    try:
        with pytest.raises(ValueError, match="exact positive integer"):
            contract.stream_to_fd(
                response, fd, budget_path=tmp_path, chunk=chunk,
                deadline_s=deadline, governor=contract.DiskGovernor(reserve_bytes=0),
            )
    finally:
        os.close(fd)
    assert response.reads == 0 and path.stat().st_size == 0


@pytest.mark.parametrize("deadline", [
    -1, float("inf"), float("nan"), True, "1",
    pytest.param(10 ** 10000, id="huge-int"),
])
def test_stream_to_fd_rejects_invalid_deadline_before_read(tmp_path, deadline):
    path = tmp_path / "preflight-stage"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    response = _CountingResponse()
    try:
        with pytest.raises(ValueError, match="finite non-negative"):
            contract.stream_to_fd(
                response, fd, budget_path=tmp_path, chunk=1,
                deadline_s=deadline, governor=contract.DiskGovernor(reserve_bytes=0),
            )
    finally:
        os.close(fd)
    assert response.reads == 0 and path.stat().st_size == 0


@pytest.mark.parametrize("mode", [0o200, 0o400, 0o700, 0o640])
def test_stream_to_fd_refuses_writable_descriptor_with_wrong_mode(tmp_path, mode):
    path = tmp_path / f"wrong-mode-{mode:o}"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    os.fchmod(fd, mode)
    response = _CountingResponse()
    try:
        with pytest.raises(ValueError, match="private regular descriptor"):
            contract.stream_to_fd(
                response, fd, budget_path=tmp_path,
                governor=contract.DiskGovernor(reserve_bytes=0),
            )
    finally:
        os.close(fd)
    assert response.reads == 0 and path.stat().st_size == 0


def test_preflight_stream_to_fd_needs_no_descriptor_or_response():
    governor = contract.DiskGovernor(reserve_bytes=0)
    assert contract.preflight_stream_to_fd(
        chunk=1, deadline_s=0, governor=governor,
    ) is governor


def test_preflight_refuses_durable_project_streaming_without_state_mutation(tmp_path):
    state = tmp_path / "state" / "acquire-project-bytes.json"
    governor = contract.DiskGovernor(
        project_max=100, project_state=state, reserve_bytes=0,
    )
    response = _CountingResponse()
    path = tmp_path / "private-stage"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with pytest.raises(ValueError, match="durable project limit"):
            contract.preflight_stream_to_fd(
                chunk=1, deadline_s=0, governor=governor,
            )
        with pytest.raises(ValueError, match="durable project limit"):
            contract.stream_to_fd(
                response, fd, budget_path=tmp_path, chunk=1,
                governor=governor,
            )
    finally:
        os.close(fd)

    assert response.reads == 0
    assert path.read_bytes() == b""
    assert not state.exists()
    assert governor.run_streamed == governor._inflight == 0


@pytest.mark.parametrize("invalid", [None, "body", bytearray(b"body"), memoryview(b"body")])
def test_stream_to_fd_rejects_non_exact_bytes_before_grant(tmp_path, invalid):
    class InvalidResponse:
        def read(self, _size=-1):
            return invalid

    path = tmp_path / "private-stage"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    governor = contract.DiskGovernor(run_max=100, reserve_bytes=0)
    try:
        with pytest.raises(contract.IncompleteAcquisition) as caught:
            contract.stream_to_fd(
                InvalidResponse(), fd, budget_path=tmp_path, chunk=8,
                governor=governor,
            )
    finally:
        os.close(fd)

    assert isinstance(caught.value.__cause__, TypeError)
    assert "exact bytes" in str(caught.value.__cause__)
    assert caught.value.bytes_written == 0
    assert caught.value.sha256 == hashlib.sha256(b"").hexdigest()
    assert path.read_bytes() == b""
    assert governor._descriptor_state == (0, {})
    assert governor.run_streamed == governor._inflight == 0


@pytest.mark.parametrize("body", [b"short-write-body", b"\x00\xff" * 20])
def test_stream_to_fd_reconciles_short_os_writes(tmp_path, monkeypatch, body):
    path = tmp_path / "short-write-stage"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    real_write = os.write

    def short_write(target, data):
        return real_write(target, data[:max(1, len(data) // 2)])

    monkeypatch.setattr(contract._os, "write", short_write)
    governor = contract.DiskGovernor(reserve_bytes=0)
    try:
        result = contract.stream_to_fd(
            io.BytesIO(body), fd, budget_path=tmp_path, chunk=len(body), governor=governor,
        )
    finally:
        os.close(fd)
    assert result == (len(body), hashlib.sha256(body).hexdigest())
    assert path.read_bytes() == body
    assert governor.run_streamed == len(body) and governor._inflight == 0


def test_stream_to_fd_charges_a_write_that_lands_then_raises(tmp_path, monkeypatch):
    path = tmp_path / "land-then-raise"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    real_write = os.write
    fault = OSError("reported after landing")

    def land_then_raise(target, data):
        real_write(target, data[:4])
        raise fault

    monkeypatch.setattr(contract._os, "write", land_then_raise)
    governor = contract.DiskGovernor(run_max=100, reserve_bytes=0)
    try:
        with pytest.raises(contract.IncompleteAcquisition) as caught:
            contract.stream_to_fd(
                io.BytesIO(b"whole-body"), fd, budget_path=tmp_path,
                chunk=64, governor=governor,
            )
    finally:
        os.close(fd)
    assert caught.value.__cause__ is fault
    assert caught.value.bytes_written == 4
    assert caught.value.sha256 == hashlib.sha256(b"whol").hexdigest()
    assert path.read_bytes() == b"whol"
    assert governor.run_streamed == 4 and governor._inflight == 0


def test_stream_to_fd_policy_stop_has_exact_terminal_accounting(tmp_path):
    path = tmp_path / "bounded-stage"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    governor = contract.DiskGovernor(run_max=5, reserve_bytes=0)
    try:
        with pytest.raises(contract.AcquisitionTruncated) as caught:
            contract.stream_to_fd(
                io.BytesIO(b"whole-body"), fd, budget_path=tmp_path,
                chunk=64, governor=governor,
            )
    finally:
        os.close(fd)
    assert caught.value.limit_kind == contract.LAYER_RUN
    assert caught.value.bytes_written == 5
    assert caught.value.sha256 == hashlib.sha256(b"whole").hexdigest()
    assert path.read_bytes() == b"whole"
    assert governor.run_streamed == 5 and governor._inflight == 0


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


def _executed_lines(function, call):
    lines = set()

    def trace(frame, event, _arg):
        if frame.f_code is function.__code__ and event == "line":
            lines.add(frame.f_lineno)
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        call()
    finally:
        sys.settrace(previous)
    return lines


def _source_line(function, fragment):
    lines, first = inspect.getsourcelines(function)
    return first + next(index for index, line in enumerate(lines) if fragment in line)


def _cancel_once(function, target_line, call, cancellation_type):
    cancellation = cancellation_type(f"descriptor stream cancellation at {target_line}")
    fired = False

    def trace(frame, event, _arg):
        nonlocal fired
        if (frame.f_code is function.__code__ and event == "line"
                and frame.f_lineno == target_line and not fired):
            fired = True
            sys.settrace(None)
            raise cancellation
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        with pytest.raises(cancellation_type) as caught:
            call()
    finally:
        sys.settrace(previous)
    assert fired
    assert caught.value is cancellation
    return cancellation


def _cancel_on_invocation(
    function, target_line, invocation, call, cancellation_type,
):
    cancellation = cancellation_type(
        f"descriptor stream cancellation at {target_line} invocation {invocation}",
    )
    hits = 0
    fired = False

    def trace(frame, event, _arg):
        nonlocal fired, hits
        if (frame.f_code is function.__code__ and event == "line"
                and frame.f_lineno == target_line):
            hits += 1
            if hits == invocation and not fired:
                fired = True
                sys.settrace(None)
                raise cancellation
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        with pytest.raises(cancellation_type) as caught:
            call()
    finally:
        sys.settrace(previous)
    assert fired
    assert caught.value is cancellation
    return cancellation


def _stream_case(tmp_path, name):
    path = tmp_path / name / "private-stage"
    path.parent.mkdir(parents=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    governor = contract.DiskGovernor(run_max=100, reserve_bytes=0)
    return path, fd, governor


@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    "operation",
    [
        contract.stream_to_fd,
        contract._stream_to_fd_body,
        contract._DescriptorStreamLedger.activate,
        contract._DescriptorStreamLedger.begin_chunk,
        contract._DescriptorStreamLedger.take,
        contract._DescriptorStreamLedger.reconcile_descriptor,
        contract._DescriptorStreamLedger.finalize,
        contract._DescriptorStreamLedger.attach,
        contract._DescriptorStreamReservation.reconcile,
        contract._DescriptorStreamReservation.take,
        contract._DescriptorStreamReservation.finalize,
        contract.DiskGovernor._activate_descriptor_stream,
        contract.DiskGovernor._take_descriptor_stream,
        contract.DiskGovernor._reconcile_descriptor_stream,
        contract.DiskGovernor._finalize_descriptor_stream,
        contract._DescriptorStreamLedger.settle,
        contract._DescriptorStreamSettlement.remember,
        contract._DescriptorStreamSettlement.reconcile,
        contract._DescriptorStreamFence._leave,
        contract._DescriptorStreamFence.__exit__,
        contract._DescriptorStreamLedger.result,
    ],
)
def test_stream_to_fd_source_line_cancellation_is_exact_and_settled(
    tmp_path, kind, operation,
):
    discovery_path, discovery_fd, discovery_governor = _stream_case(
        tmp_path, "discovery",
    )
    try:
        lines = _executed_lines(
            operation,
            lambda: contract.stream_to_fd(
                io.BytesIO(b"known-body"), discovery_fd,
                budget_path=discovery_path.parent, chunk=64,
                governor=discovery_governor,
            ),
        )
    finally:
        os.close(discovery_fd)
    assert lines

    for index, target_line in enumerate(sorted(lines)):
        path, fd, governor = _stream_case(
            tmp_path, f"{operation.__name__}-{kind.__name__}-{index}",
        )
        try:
            cancellation = _cancel_once(
                operation, target_line,
                lambda: contract.stream_to_fd(
                    io.BytesIO(b"known-body"), fd, budget_path=path.parent,
                    chunk=64, governor=governor,
                ),
                kind,
            )
        finally:
            os.close(fd)
        retained = path.read_bytes()
        if hasattr(cancellation, "bytes_written"):
            assert cancellation.bytes_written == len(retained), target_line
            assert cancellation.sha256 == hashlib.sha256(retained).hexdigest(), target_line
        else:
            first_fence = _source_line(contract.stream_to_fd, "with _DescriptorStreamFence(settlement):")
            assert operation is contract.stream_to_fd and target_line <= first_fence, target_line
            assert retained == b"", target_line
        assert governor.run_streamed == len(retained), target_line
        assert governor._inflight == 0, target_line
        assert governor._descriptor_state == (len(retained), {}), target_line


@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit])
def test_second_fence_exit_source_line_cancellation_has_terminal_metadata(
    tmp_path, kind,
):
    operation = contract._DescriptorStreamFence.__exit__
    discovery_path, discovery_fd, discovery_governor = _stream_case(
        tmp_path, "second-fence-discovery",
    )
    try:
        lines = _executed_lines(
            operation,
            lambda: contract.stream_to_fd(
                io.BytesIO(b"known-body"), discovery_fd,
                budget_path=discovery_path.parent, chunk=64,
                governor=discovery_governor,
            ),
        )
    finally:
        os.close(discovery_fd)
    assert lines

    for index, target_line in enumerate(sorted(lines)):
        path, fd, governor = _stream_case(
            tmp_path, f"second-fence-{kind.__name__}-{index}",
        )
        try:
            cancellation = _cancel_on_invocation(
                operation, target_line, 2,
                lambda: contract.stream_to_fd(
                    io.BytesIO(b"known-body"), fd,
                    budget_path=path.parent, chunk=64, governor=governor,
                ),
                kind,
            )
        finally:
            os.close(fd)

        retained = path.read_bytes()
        assert retained == b"known-body", target_line
        assert cancellation.bytes_written == len(retained), target_line
        assert cancellation.sha256 == hashlib.sha256(retained).hexdigest(), target_line
        assert governor._descriptor_state == (len(retained), {}), target_line
        assert governor.run_streamed == len(retained), target_line
        assert governor._inflight == 0, target_line


def _sync_governor_under_stream_fences(ledger, governor):
    settlement = contract._DescriptorStreamSettlement(ledger)
    with contract._DescriptorStreamFence(settlement):
        with contract._DescriptorStreamFence(settlement):
            governor._sync_descriptor_totals()


@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit])
def test_governor_total_sync_source_lines_are_fenced(tmp_path, kind):
    discovery_path, discovery_fd, discovery_governor = _stream_case(
        tmp_path, "sync-discovery",
    )
    try:
        discovery_ledger = contract._DescriptorStreamLedger(
            discovery_fd, discovery_path.parent, discovery_governor,
        )
        lines = _executed_lines(
            contract.DiskGovernor._sync_descriptor_totals,
            lambda: _sync_governor_under_stream_fences(
                discovery_ledger, discovery_governor,
            ),
        )
    finally:
        os.close(discovery_fd)

    for index, target_line in enumerate(sorted(lines)):
        path, fd, governor = _stream_case(tmp_path, f"sync-{kind.__name__}-{index}")
        try:
            ledger = contract._DescriptorStreamLedger(fd, path.parent, governor)
            cancellation = _cancel_once(
                contract.DiskGovernor._sync_descriptor_totals, target_line,
                lambda: _sync_governor_under_stream_fences(ledger, governor), kind,
            )
        finally:
            os.close(fd)
        assert cancellation.bytes_written == 0
        assert cancellation.sha256 == hashlib.sha256(b"").hexdigest()
        assert governor.run_streamed == governor._inflight == 0
        assert governor._descriptor_state == (0, {})


@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit])
def test_governor_reservation_creation_has_no_pre_fence_effect(tmp_path, kind):
    operation = contract.DiskGovernor._begin_descriptor_stream
    discovery = contract.DiskGovernor(run_max=100, reserve_bytes=0)
    lines = _executed_lines(operation, discovery._begin_descriptor_stream)
    for target_line in sorted(lines):
        governor = contract.DiskGovernor(run_max=100, reserve_bytes=0)
        _cancel_once(operation, target_line, governor._begin_descriptor_stream, kind)
        assert governor.run_streamed == governor._inflight == 0
        assert governor._descriptor_state == (0, {})


@pytest.mark.parametrize(
    ("counter", "ceiling", "layer"),
    [
        ("run_streamed", "run_max", contract.LAYER_RUN),
        ("project_streamed", "project_max", contract.LAYER_PROJECT),
    ],
)
def test_legacy_governor_preserves_external_counter_mutation(
    tmp_path, counter, ceiling, layer,
):
    governor = contract.DiskGovernor(
        **{ceiling: 100}, reserve_bytes=0,
    )
    setattr(governor, counter, 60)

    granted, binding = governor.take(tmp_path, 0, 50)
    assert (granted, binding) == (40, layer)
    assert getattr(governor, counter) == 60
    assert governor._inflight == 40

    governor.commit(15)
    governor.settle(granted, 15)
    assert getattr(governor, counter) == 75
    expected_run = 15 if counter == "project_streamed" else 75
    assert governor.run_streamed == expected_run
    assert governor._inflight == 0


def test_terminal_descriptor_reservations_are_folded_and_removed(tmp_path):
    governor = contract.DiskGovernor(run_max=1000, reserve_bytes=0)
    bodies = [f"body-{index}".encode() for index in range(25)]

    for index, body in enumerate(bodies):
        path = tmp_path / f"private-stage-{index}"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            assert contract.stream_to_fd(
                io.BytesIO(body), fd, budget_path=tmp_path, chunk=3,
                governor=governor,
            ) == (len(body), hashlib.sha256(body).hexdigest())
        finally:
            os.close(fd)

    total = sum(map(len, bodies))
    assert governor._descriptor_state == (total, {})
    assert governor.run_streamed == total
    assert governor._inflight == 0


def test_terminal_charge_can_grow_to_a_later_observation_exactly_once(tmp_path):
    path = tmp_path / "private-stage"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    governor = contract.DiskGovernor(run_max=100, reserve_bytes=0)
    ledger = contract._DescriptorStreamLedger(fd, tmp_path, governor)
    try:
        ledger.activate()
        ledger.begin_chunk(b"body")
        ledger.take()
        os.write(fd, b"body")
        ledger.reconcile_descriptor(terminal=True)
        assert governor._descriptor_state == (0, {
            ledger.reservation.token: (4, 4, True),
        })

        alias = os.open(path, os.O_WRONLY | os.O_APPEND)
        try:
            os.write(alias, b"later")
        finally:
            os.close(alias)
        with pytest.raises(OSError, match="exclusive sequential ownership"):
            ledger.settle()
        assert ledger.accounting_observed == 9
        assert ledger.accounting_charged == 9

        ledger.finalize()
        ledger.finalize()
    finally:
        os.close(fd)

    assert path.stat().st_size == 9
    assert governor._descriptor_state == (9, {})
    assert governor.run_streamed == 9
    assert governor._inflight == 0


@pytest.mark.parametrize("limit_kind", ["run", "project", "reserve"])
def test_concurrent_descriptor_streams_cannot_double_spend(tmp_path, limit_kind):
    paths = [tmp_path / f"private-stage-{index}" for index in range(2)]
    fds = [os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
           for path in paths]
    if limit_kind == "run":
        governor = contract.DiskGovernor(run_max=10, reserve_bytes=0)
        expected_layer = contract.LAYER_RUN
    elif limit_kind == "project":
        governor = contract.DiskGovernor(project_max=10, reserve_bytes=0)
        expected_layer = contract.LAYER_PROJECT
    else:
        def free_space(_path):
            return 15 - sum(path.stat().st_size for path in paths)

        governor = contract.DiskGovernor(reserve_bytes=5, free_fn=free_space)
        expected_layer = contract.LAYER_RESERVE

    start = threading.Barrier(2)
    outcomes = [None, None]

    class ConcurrentResponse(io.BytesIO):
        def __init__(self, body):
            super().__init__(body)
            self.first = True

        def read(self, size=-1):
            if self.first:
                self.first = False
                start.wait(timeout=5)
            return super().read(size)

    def stream(index):
        try:
            outcomes[index] = contract.stream_to_fd(
                ConcurrentResponse(b"x" * 8), fds[index], budget_path=tmp_path,
                chunk=8, governor=governor,
            )
        except BaseException as exc:
            outcomes[index] = exc

    threads = [threading.Thread(target=stream, args=(index,)) for index in range(2)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        assert not any(thread.is_alive() for thread in threads)
    finally:
        for fd in fds:
            os.close(fd)

    truncated = [outcome for outcome in outcomes
                 if isinstance(outcome, contract.AcquisitionTruncated)]
    assert len(truncated) == 1
    assert truncated[0].limit_kind == expected_layer
    total = sum(path.stat().st_size for path in paths)
    assert total == 10 if limit_kind != "reserve" else 8 <= total <= 10
    assert governor._descriptor_state == (total, {})
    assert governor.run_streamed == total
    assert governor._inflight == 0
    if limit_kind == "project":
        assert governor.project_streamed == total


def test_cancelling_one_stream_does_not_settle_another_active_token(
    tmp_path, monkeypatch,
):
    first_path = tmp_path / "cancelling-stage"
    second_path = tmp_path / "blocked-stage"
    first_fd = os.open(first_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    second_fd = os.open(second_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    governor = contract.DiskGovernor(run_max=100, reserve_bytes=0)
    cancellation = KeyboardInterrupt("cancel only the first response")
    blocked_write = threading.Event()
    release_write = threading.Event()
    first_done = threading.Event()
    real_write = os.write
    blocked_once = False
    outcomes = [None, None]

    def coordinated_write(target, data):
        nonlocal blocked_once
        if target == second_fd and not blocked_once:
            blocked_once = True
            blocked_write.set()
            if not release_write.wait(timeout=5):
                raise TimeoutError("test did not release the blocked stream")
        return real_write(target, data)

    monkeypatch.setattr(contract._os, "write", coordinated_write)

    class CancellingResponse:
        def __init__(self):
            self.reads = 0

        def read(self, _size=-1):
            self.reads += 1
            if self.reads == 1:
                return b"A"
            if not blocked_write.wait(timeout=5):
                raise TimeoutError("other stream never became active")
            raise cancellation

    def first_stream():
        try:
            outcomes[0] = contract.stream_to_fd(
                CancellingResponse(), first_fd, budget_path=tmp_path,
                chunk=8, governor=governor,
            )
        except BaseException as exc:
            outcomes[0] = exc
        finally:
            first_done.set()

    def second_stream():
        try:
            outcomes[1] = contract.stream_to_fd(
                io.BytesIO(b"BBBB"), second_fd, budget_path=tmp_path,
                chunk=8, governor=governor,
            )
        except BaseException as exc:
            outcomes[1] = exc

    first_thread = threading.Thread(target=first_stream)
    second_thread = threading.Thread(target=second_stream)
    try:
        second_thread.start()
        first_thread.start()
        assert first_done.wait(timeout=5)
        with governor._lock:
            settled, active = governor._descriptor_state
            assert settled == 1
            assert list(active.values()) == [(4, 0, False)]
            assert governor.run_streamed == 1
            assert governor._inflight == 4
        release_write.set()
        first_thread.join(timeout=5)
        second_thread.join(timeout=5)
        assert not first_thread.is_alive() and not second_thread.is_alive()
    finally:
        release_write.set()
        first_thread.join(timeout=5)
        second_thread.join(timeout=5)
        os.close(second_fd)
        os.close(first_fd)

    assert outcomes[0] is cancellation
    assert cancellation.bytes_written == 1
    assert cancellation.sha256 == hashlib.sha256(b"A").hexdigest()
    assert outcomes[1] == (4, hashlib.sha256(b"BBBB").hexdigest())
    assert governor._descriptor_state == (5, {})
    assert governor.run_streamed == 5
    assert governor._inflight == 0


@pytest.mark.parametrize("violation", ["aliased-write", "truncate", "offset"])
def test_descriptor_ownership_violation_fails_closed(
    tmp_path, monkeypatch, violation,
):
    body = b"whole-body"
    path = tmp_path / f"private-stage-{violation}"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    governor = contract.DiskGovernor(run_max=len(body), reserve_bytes=0)
    real_write = os.write
    fired = False

    def violating_write(target, data):
        nonlocal fired
        if fired:
            return real_write(target, data)
        fired = True
        if violation == "aliased-write":
            landed = real_write(target, data[:4])
            alias = os.open(path, os.O_WRONLY)
            try:
                os.lseek(alias, 4, os.SEEK_SET)
                real_write(alias, data[4:])
            finally:
                os.close(alias)
            return landed
        landed = real_write(target, data)
        if violation == "truncate":
            os.ftruncate(target, 0)
        else:
            os.lseek(target, 0, os.SEEK_SET)
        return landed

    monkeypatch.setattr(contract._os, "write", violating_write)
    try:
        with pytest.raises(contract.IncompleteAcquisition) as caught:
            contract.stream_to_fd(
                io.BytesIO(body), fd, budget_path=tmp_path, chunk=len(body),
                governor=governor,
            )
    finally:
        os.close(fd)

    assert fired
    assert isinstance(caught.value.__cause__, OSError)
    assert "exclusive sequential ownership" in str(caught.value.__cause__)
    assert caught.value.bytes_written == path.stat().st_size
    assert caught.value.sha256 is None
    assert caught.value.content_uncertain is True
    assert caught.value.acquisition_observed_bytes == path.stat().st_size
    assert "exclusive sequential ownership" in (
        caught.value.acquisition_accounting_uncertainty
    )
    assert caught.value.acquisition_accounting_charged_bytes >= len(body)
    settled, active = governor._descriptor_state
    assert active == {}
    assert settled == caught.value.acquisition_accounting_charged_bytes
    assert governor.run_streamed == settled
    assert governor._inflight == 0
    assert governor.run_streamed + governor._inflight >= path.stat().st_size
    assert governor.take(tmp_path, 0, 1) == (0, contract.LAYER_RUN)


@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("operation", [
    contract._DescriptorStreamLedger.refuse_ownership,
    contract._DescriptorStreamReservation.forfeit,
    contract.DiskGovernor._forfeit_descriptor_stream,
])
def test_ownership_forfeit_source_line_cancellation_is_terminal(
    tmp_path, monkeypatch, kind, operation,
):
    body = b"uncertain-body"
    real_write = os.write

    def offset_after_write(target, data):
        landed = real_write(target, data)
        os.lseek(target, 0, os.SEEK_SET)
        return landed

    monkeypatch.setattr(contract._os, "write", offset_after_write)

    def invoke(path, fd, governor):
        try:
            contract.stream_to_fd(
                io.BytesIO(body), fd, budget_path=path.parent,
                chunk=len(body), governor=governor,
            )
        except contract.IncompleteAcquisition:
            pass

    discovery_path, discovery_fd, discovery_governor = _stream_case(
        tmp_path, "forfeit-discovery",
    )
    try:
        lines = _executed_lines(
            operation,
            lambda: invoke(discovery_path, discovery_fd, discovery_governor),
        )
    finally:
        os.close(discovery_fd)
    assert lines

    for index, target_line in enumerate(sorted(lines)):
        path, fd, governor = _stream_case(
            tmp_path, f"forfeit-{operation.__name__}-{kind.__name__}-{index}",
        )
        try:
            cancellation = _cancel_once(
                operation, target_line,
                lambda: contract.stream_to_fd(
                    io.BytesIO(body), fd, budget_path=path.parent,
                    chunk=len(body), governor=governor,
                ),
                kind,
            )
        finally:
            os.close(fd)

        assert cancellation.bytes_written == len(body), target_line
        assert cancellation.sha256 is None, target_line
        assert cancellation.content_uncertain is True, target_line
        assert cancellation.acquisition_accounting_charged_bytes == len(body), target_line
        assert governor._descriptor_state == (len(body), {}), target_line
        assert governor.run_streamed == len(body), target_line
        assert governor._inflight == 0, target_line


def test_cleanup_fault_never_masks_exact_cancellation(tmp_path, monkeypatch):
    path, fd, governor = _stream_case(tmp_path, "cleanup-precedence")
    cancellation = KeyboardInterrupt("exact response cancellation")
    real_reconcile = contract._DescriptorStreamLedger.reconcile_descriptor
    calls = {"count": 0}

    def faulty_reconcile(self, *args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 2:
            raise OSError("later cleanup fault")
        return real_reconcile(self, *args, **kwargs)

    monkeypatch.setattr(
        contract._DescriptorStreamLedger, "reconcile_descriptor", faulty_reconcile,
    )
    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            contract.stream_to_fd(
                _CancellingResponse(cancellation), fd, budget_path=path.parent,
                chunk=64, governor=governor,
            )
    finally:
        os.close(fd)
    assert caught.value is cancellation
    assert governor._inflight == 0
    assert any("later cleanup fault" in str(error)
               for error in cancellation.acquisition_cleanup_errors)


def test_cleanup_fault_attaches_without_replacing_incomplete(tmp_path, monkeypatch):
    path, fd, governor = _stream_case(tmp_path, "incomplete-cleanup")
    response_fault = OSError("response broke")
    real_reconcile = contract._DescriptorStreamLedger.reconcile_descriptor
    calls = {"count": 0}

    class BrokenResponse:
        def read(self, _size=-1):
            raise response_fault

    def faulty_reconcile(self, *args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("cleanup broke")
        return real_reconcile(self, *args, **kwargs)

    monkeypatch.setattr(
        contract._DescriptorStreamLedger, "reconcile_descriptor", faulty_reconcile,
    )
    try:
        with pytest.raises(contract.IncompleteAcquisition) as caught:
            contract.stream_to_fd(
                BrokenResponse(), fd, budget_path=path.parent,
                chunk=64, governor=governor,
            )
    finally:
        os.close(fd)
    assert caught.value.__cause__ is response_fault
    assert any("cleanup broke" in str(error)
               for error in caught.value.acquisition_cleanup_errors)
    assert governor._inflight == 0
