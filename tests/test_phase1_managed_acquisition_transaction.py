"""Phase 1 managed HTTP acquisition transaction acceptance tests.

These cases exercise the public ``scoped_get_file`` surface.  The store and
private-filesystem machinery stays opaque: a managed destination is recognized
before contact, a per-destination lease spans contact while Run mutations stay
short, and returned facts are reconciled before they become immutable.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import select
import signal
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import contract, events, evidence, fetch, store


pytestmark = pytest.mark.offline


class _Response(io.BytesIO):
    status = 200
    headers: dict = {}


class _CloseCommittedWithFault(_Response):
    """Close the exact response, then report an ordinary cleanup fault once."""

    def __init__(self, body: bytes):
        super().__init__(body)
        self._reported = False

    def close(self):
        super().close()
        if not self._reported:
            self._reported = True
            raise OSError("response close reported after commit")


class _CloseCancels(_Response):
    def __init__(self, body: bytes, cancellation: BaseException):
        super().__init__(body)
        self.cancellation = cancellation
        self._reported = False

    def close(self):
        super().close()
        if not self._reported:
            self._reported = True
            raise self.cancellation


class _LockedCloseError(Exception):
    """An ordinary cleanup fault that rejects ad-hoc exception attributes."""

    __slots__ = ()

    def __setattr__(self, _name, _value):
        raise TypeError("locked exception")


class _CloseLockedWithFault(_Response):
    def __init__(self, body: bytes):
        super().__init__(body)
        self._reported = False

    def close(self):
        super().close()
        if not self._reported:
            self._reported = True
            raise _LockedCloseError("immutable response close fault")


class _PrefixThenCancel:
    status = 200
    headers: dict = {}

    def __init__(self, prefix: bytes, cancellation: BaseException):
        self.prefix = prefix
        self.cancellation = cancellation
        self.reads = 0
        self.closed = False

    def read(self, _size=-1):
        self.reads += 1
        if self.reads == 1:
            return self.prefix
        raise self.cancellation

    def close(self):
        self.closed = True
        raise OSError("response close must not mask cancellation")


def _running_context(project: Path, run_id="managed-acquisition"):
    run = store.Run.create(project, "acme.example", run_id=run_id)
    run.write_state("running")
    ctx = SimpleNamespace(
        run=run,
        profile=SimpleNamespace(http_rl=0),
        scope=SimpleNamespace(
            active_allowed=lambda _host: True,
            in_scope=lambda _host: True,
            is_oos=lambda _host: False,
        ),
    )
    dest = run.raw_path("params", "managed", "body.bin")
    return ctx, run, dest


def _allow_contact(monkeypatch):
    monkeypatch.setattr(
        fetch.netguard, "contact_state",
        lambda _host, block_private=False: ("contact", None, None),
    )


def _serve(monkeypatch, response, calls: list[str]):
    _allow_contact(monkeypatch)

    def opened(request, _timeout, opener=None):
        calls.append(request.full_url)
        return 200, {}, response

    monkeypatch.setattr(fetch, "_open_no_follow", opened)


def _receipt_path(dest: Path) -> Path:
    return dest.with_name(dest.name + fetch._RECEIPT_SUFFIX)


def _wait_child(pid: int, timeout=5.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return status
        time.sleep(0.01)
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    pytest.fail(f"managed-acquisition child {pid} did not settle")


def _fd_target(fd: int) -> str:
    try:
        return os.readlink(f"/proc/self/fd/{fd}")
    except OSError:
        return ""


def _unlink_target(path, dir_fd=None) -> Path:
    candidate = Path(path)
    if candidate.is_absolute() or dir_fd is None:
        return candidate
    parent = _fd_target(dir_fd)
    return Path(parent) / candidate if parent else candidate


def _run_diagnostics(run) -> str:
    rows = list(run.read("review"))
    event_path = run.dir / "events.jsonl"
    if event_path.exists():
        rows.extend(json.loads(line) for line in event_path.read_text().splitlines() if line.strip())
    return json.dumps(rows, default=str).lower()


def test_managed_path_requires_the_exact_run_owner_before_contact(tmp_path, monkeypatch):
    _ctx, run, dest = _running_context(tmp_path, "owner-first")
    fake_ctx = SimpleNamespace(
        run=SimpleNamespace(dir=run.dir),
        profile=SimpleNamespace(http_rl=0),
        scope=SimpleNamespace(active_allowed=lambda _host: True),
    )
    calls: list[str] = []
    _serve(monkeypatch, _Response(b"must not be requested"), calls)

    acquired, final, status = fetch.scoped_get_file(
        fake_ctx, "https://t/owner", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert calls == []
    assert acquired is not None and acquired.contacted is False
    assert not acquired.complete
    assert "owner" in acquired.disposition or "managed" in acquired.disposition
    assert (final, status) == ("https://t/owner", 0)
    assert not dest.exists() and not _receipt_path(dest).exists()


def test_managed_path_owned_by_another_run_is_refused_before_contact(tmp_path, monkeypatch):
    ctx, _run, _own_dest = _running_context(tmp_path, "caller-run")
    foreign = store.Run.create(tmp_path, "acme.example", run_id="foreign-run")
    foreign.write_state("running")
    dest = foreign.raw_path("params", "managed", "foreign.bin")
    calls: list[str] = []
    _serve(monkeypatch, _Response(b"must not cross runs"), calls)

    acquired, _final, status = fetch.scoped_get_file(
        ctx, "https://t/foreign", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert calls == [] and status == 0
    assert acquired is not None and acquired.contacted is False and not acquired.complete
    assert not dest.exists() and not _receipt_path(dest).exists()


def test_lexically_managed_but_unauthenticatable_path_never_falls_back_to_legacy(
    tmp_path, monkeypatch,
):
    run_dir = tmp_path / "recon" / "planted-run"
    run_dir.mkdir(parents=True)
    dest = run_dir / "raw" / "params" / "body.bin"
    fake_ctx = SimpleNamespace(
        run=SimpleNamespace(dir=run_dir),
        profile=SimpleNamespace(http_rl=0),
        scope=SimpleNamespace(active_allowed=lambda _host: True),
    )
    calls: list[str] = []
    _serve(monkeypatch, _Response(b"must not become ambient"), calls)

    acquired, _final, status = fetch.scoped_get_file(
        fake_ctx, "https://t/planted", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert calls == [] and status == 0
    assert acquired is not None and acquired.contacted is False and not acquired.complete
    assert not dest.exists() and not dest.parent.exists()


def test_symlink_alias_into_managed_run_cannot_bypass_owner_classification(
    tmp_path, monkeypatch,
):
    _ctx, run, _dest = _running_context(tmp_path, "aliased-run")
    alias = tmp_path / "raw-alias"
    alias.symlink_to(run.raw, target_is_directory=True)
    dest = alias / "aliased.bin"
    fake_ctx = SimpleNamespace(
        run=SimpleNamespace(dir=run.dir),
        profile=SimpleNamespace(http_rl=0),
        scope=SimpleNamespace(active_allowed=lambda _host: True),
    )
    calls: list[str] = []
    _serve(monkeypatch, _Response(b"must not follow alias"), calls)

    acquired, _final, status = fetch.scoped_get_file(
        fake_ctx, "https://t/alias", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert calls == [] and status == 0
    assert acquired is not None and acquired.contacted is False and not acquired.complete
    assert not (run.raw / "aliased.bin").exists()


@pytest.mark.parametrize("relative", [
    (),
    ("state", "lease.json"),
    ("campaigns", "active.json"),
    ("bad run!", "raw", "body.bin"),
    ("..bad", "body.bin"),
    ("direct.bin",),
])
def test_reserved_recon_namespace_without_run_authority_never_uses_legacy_io(
    tmp_path, monkeypatch, relative,
):
    dest = tmp_path.joinpath("recon", *relative)
    ctx = SimpleNamespace(
        profile=SimpleNamespace(http_rl=0),
        scope=SimpleNamespace(active_allowed=lambda _host: True),
    )
    calls: list[str] = []
    _serve(monkeypatch, _Response(b"must not enter the control namespace"), calls)

    acquired, _final, status = fetch.scoped_get_file(
        ctx, "https://t/reserved", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert calls == [] and status == 0
    assert acquired is not None and acquired.contacted is False and not acquired.complete
    assert "managed" in acquired.disposition
    assert not dest.exists()


def test_resolved_alias_into_reserved_recon_namespace_never_uses_legacy_io(
    tmp_path, monkeypatch,
):
    reserved = tmp_path / "recon" / "state"
    reserved.mkdir(parents=True)
    alias = tmp_path / "state-alias"
    alias.symlink_to(reserved, target_is_directory=True)
    dest = alias / "lease.json"
    ctx = SimpleNamespace(
        profile=SimpleNamespace(http_rl=0),
        scope=SimpleNamespace(active_allowed=lambda _host: True),
    )
    calls: list[str] = []
    _serve(monkeypatch, _Response(b"must not follow the control alias"), calls)

    acquired, _final, status = fetch.scoped_get_file(
        ctx, "https://t/reserved-alias", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert calls == [] and status == 0
    assert acquired is not None and acquired.contacted is False and not acquired.complete
    assert "managed" in acquired.disposition
    assert not (reserved / "lease.json").exists()


@pytest.mark.parametrize("invalid", [
    {"chunk": 0},
    {"chunk": True},
    {"deadline_s": float("inf")},
    {"deadline_s": -1},
    {"governor": object()},
])
def test_invalid_stream_shape_is_rejected_before_contact_or_stage(
    tmp_path, monkeypatch, invalid,
):
    ctx, _run, dest = _running_context(tmp_path, "precontact-shape")
    calls: list[str] = []
    _serve(monkeypatch, _Response(b"false empty success"), calls)

    with pytest.raises((TypeError, ValueError)):
        fetch.scoped_get_file(
            ctx, "https://t/shape", dest, "t",
            **({"governor": contract.DiskGovernor(reserve_bytes=0)} | invalid),
        )

    assert calls == []
    assert not dest.exists() and not dest.with_name(dest.name + ".part").exists()
    assert not _receipt_path(dest).exists()


@pytest.mark.parametrize(("url", "invalid"), [
    (None, {}),
    ("", {}),
    ("://", {}),
    ("ftp://t/body", {}),
    ("https:///missing-host", {}),
    ("https://t/body with space", {}),
    ("https://t/body\x00control", {}),
    ("https://[", {}),
    ("https://t/body", {"method": 7}),
    ("https://t/body", {"method": ""}),
    ("https://t/body", {"method": "G ET"}),
    ("https://t/body", {"method": "GET\r\nX-Evil"}),
    ("https://t/body", {"method": "G€T"}),
    ("https://t/body", {"data": "not-bytes"}),
    ("https://t/body", {"data": bytearray(b"mutable")}),
    ("https://t/body", {"headers": 7}),
    ("https://t/body", {"headers": {None: "x"}}),
    ("https://t/body", {"headers": {"X-Test": 7}}),
    ("https://t/body", {"headers": {"Bad:Name": "x"}}),
    ("https://t/body", {"headers": {"Bad\nName": "x"}}),
    ("https://t/body", {"headers": {"é": "x"}}),
    ("https://t/body", {"headers": {"X-Test": "bad\r\nvalue"}}),
    ("https://t/body", {"headers": {"X-Test": "bad\x00value"}}),
    ("https://t/body", {"headers": {"X-Test": "not Latin-1 €"}}),
    ("https://t/body", {"origin_host": 7}),
    ("https://t/body", {"origin_host": "bad host"}),
    ("https://t/body", {"timeout": True}),
    ("https://t/body", {"timeout": -1}),
    ("https://t/body", {"timeout": float("inf")}),
    ("https://t/body", {"max_redirects": True}),
    ("https://t/body", {"max_redirects": -1}),
])
def test_invalid_managed_request_shape_is_rejected_before_claim_or_contact(
    tmp_path, monkeypatch, url, invalid,
):
    ctx, run, dest = _running_context(
        tmp_path, f"request-shape-{len(str(invalid))}",
    )
    calls: list[str] = []
    _serve(monkeypatch, _Response(b"false managed success"), calls)
    origin = invalid.pop("origin_host", "t")

    with pytest.raises((TypeError, ValueError)):
        fetch.scoped_get_file(
            ctx, url, dest, origin,
            governor=contract.DiskGovernor(reserve_bytes=0), **invalid,
        )

    assert calls == []
    assert not dest.exists() and not dest.with_name(dest.name + ".part").exists()
    assert not _receipt_path(dest).exists()
    claim_dir = tmp_path / "recon" / "state" / "claims" / run.run_id
    assert list(claim_dir.glob("*.claim")) == []


class _OnePassHeaders(Mapping):
    def __init__(self):
        self.iterations = 0
        self.values = {"X-Frozen": "original"}

    def __iter__(self):
        self.iterations += 1
        if self.iterations > 1:
            raise OSError("headers were iterated after preflight")
        yield from self.values
        self.values["X-Frozen"] = "mutated-after-snapshot"

    def __len__(self):
        return len(self.values)

    def __getitem__(self, key):
        return self.values[key]


def test_managed_headers_are_materialized_once_before_claim(tmp_path, monkeypatch):
    ctx, run, dest = _running_context(tmp_path, "headers-frozen")
    headers = _OnePassHeaders()
    calls: list[tuple[str, list[tuple[str, str]]]] = []
    _allow_contact(monkeypatch)

    def opened(request, _timeout, opener=None):
        calls.append((request.full_url, request.header_items()))
        return 200, {}, _Response(b"frozen header body")

    monkeypatch.setattr(fetch, "_open_no_follow", opened)
    acquired, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/frozen-headers", dest, "t", headers=headers,
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert acquired.complete and headers.iterations == 1
    sent = {name.lower(): value for name, value in calls[0][1]}
    assert sent["x-frozen"] == "original"
    assert dest.read_bytes() == b"frozen header body"
    claim_dir = tmp_path / "recon" / "state" / "claims" / run.run_id
    assert list(claim_dir.glob("*.claim")) == []


def test_sealed_managed_run_is_refused_before_contact(tmp_path, monkeypatch):
    ctx, run, dest = _running_context(tmp_path, "sealed-precontact")
    run.begin_finalization()
    calls: list[str] = []
    _serve(monkeypatch, _Response(b"too late"), calls)

    acquired, final, status = fetch.scoped_get_file(
        ctx, "https://t/sealed", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert calls == []
    assert acquired is not None and acquired.contacted is False
    assert not acquired.complete and "sealed" in (acquired.error or "").lower()
    assert (final, status) == ("https://t/sealed", 0)


def test_response_close_fault_does_not_mask_complete_owned_result(tmp_path, monkeypatch):
    ctx, _run, dest = _running_context(tmp_path, "close-after-complete")
    body = b"complete response despite close fault\x00\xff"
    calls: list[str] = []
    _serve(monkeypatch, _CloseCommittedWithFault(body), calls)

    acquired, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/complete", dest, "t", chunk=7,
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert acquired.complete and acquired.disposition == "complete"
    assert acquired.bytes == len(body) and dest.read_bytes() == body
    assert "close" in (acquired.error or "").lower()
    assert len(calls) == 1 and _receipt_path(dest).exists()

    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("owned evidence was requested twice"),
    )
    replay, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/complete", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert replay.complete and replay.contacted is False
    assert replay.disposition == "replayed-complete"


def test_hostile_ordinary_close_exception_is_still_a_terminal_diagnostic(
    tmp_path, monkeypatch,
):
    ctx, _run, dest = _running_context(tmp_path, "locked-close-after-complete")
    body = b"whole body before immutable close fault"
    calls: list[str] = []
    _serve(monkeypatch, _CloseLockedWithFault(body), calls)

    acquired, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/locked-close", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert calls == ["https://t/locked-close"]
    assert acquired.complete and acquired.path == dest
    assert acquired.disposition == "complete"
    assert "immutable response close fault" in acquired.error
    assert dest.read_bytes() == body and _receipt_path(dest).exists()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_exact_response_close_cancellation_propagates_after_complete_ownership(
    tmp_path, monkeypatch, cancellation_type,
):
    ctx, run, dest = _running_context(tmp_path, f"close-{cancellation_type.__name__}")
    body = b"EOF was observed before response cleanup"
    cancellation = cancellation_type("exact response close cancellation")
    calls: list[str] = []
    _serve(monkeypatch, _CloseCancels(body, cancellation), calls)

    with pytest.raises(cancellation_type) as caught:
        fetch.scoped_get_file(
            ctx, "https://t/close-cancel", dest, "t", chunk=9,
            governor=contract.DiskGovernor(reserve_bytes=0),
        )

    assert caught.value is cancellation and dest.read_bytes() == body
    assert _receipt_path(dest).exists()
    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("complete body was requested twice"),
    )
    replay, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/close-cancel", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert replay.complete and replay.disposition == "replayed-complete"
    run.begin_finalization()  # public proof that no acquisition claim leaked


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_exact_cancellation_wins_over_response_close_and_keeps_owned_prefix(
    tmp_path, monkeypatch, cancellation_type,
):
    ctx, run, dest = _running_context(tmp_path, f"cancel-{cancellation_type.__name__}")
    prefix = b"known managed prefix\x00\xff"
    cancellation = cancellation_type("exact managed cancellation")
    response = _PrefixThenCancel(prefix, cancellation)
    calls: list[str] = []
    _serve(monkeypatch, response, calls)

    with pytest.raises(cancellation_type) as caught:
        fetch.scoped_get_file(
            ctx, "https://t/cancel", dest, "t", chunk=64,
            governor=contract.DiskGovernor(reserve_bytes=0),
        )

    assert caught.value is cancellation
    assert response.closed and calls == ["https://t/cancel"]
    part = dest.with_name(dest.name + ".part")
    assert part.read_bytes() == prefix
    receipt = json.loads(_receipt_path(dest).read_text())
    assert receipt["complete"] is False and receipt["bytes"] == len(prefix)
    assert "cancel" in receipt.get("error", "").lower()
    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("cancelled evidence was requested twice"),
    )
    replay, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/cancel", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert replay.disposition == "replayed-incomplete"
    assert replay.partial == part and replay.bytes == len(prefix)
    run.begin_finalization()  # public proof that no acquisition claim leaked


def test_same_path_threads_serialize_contact_and_replay(tmp_path, monkeypatch):
    ctx, run, dest = _running_context(tmp_path, "thread-serialization")
    body = b"one contact, one terminal body"
    entered = threading.Event()
    release = threading.Event()
    calls: list[str] = []
    calls_lock = threading.Lock()
    _allow_contact(monkeypatch)

    class BlockingResponse(_Response):
        def read(self, size=-1):
            entered.set()
            assert release.wait(5), "test did not release the response"
            return super().read(size)

    def opened(request, _timeout, opener=None):
        with calls_lock:
            calls.append(request.full_url)
        return 200, {}, BlockingResponse(body)

    monkeypatch.setattr(fetch, "_open_no_follow", opened)
    results = []
    errors = []

    def acquire(opened_run):
        local = SimpleNamespace(run=opened_run, profile=ctx.profile, scope=ctx.scope)
        try:
            results.append(fetch.scoped_get_file(
                local, "https://t/serialized", dest, "t", chunk=8,
                governor=contract.DiskGovernor(reserve_bytes=0),
            )[0])
        except BaseException as exc:  # assertion reports both thread failures
            errors.append(exc)

    first = threading.Thread(target=acquire, args=(run,))
    second_run = store.Run.open(tmp_path, "acme.example", run.run_id)
    second = threading.Thread(target=acquire, args=(second_run,))
    first.start()
    assert entered.wait(5)
    second.start()
    time.sleep(0.05)
    assert calls == ["https://t/serialized"]
    release.set()
    first.join(5); second.join(5)

    assert not errors and not first.is_alive() and not second.is_alive()
    assert len(calls) == 1 and dest.read_bytes() == body
    assert sorted((item.contacted, item.disposition) for item in results) == [
        (False, "replayed-complete"), (True, "complete"),
    ]


def test_same_path_processes_make_one_contact_then_replay(tmp_path, monkeypatch):
    ctx, run, dest = _running_context(tmp_path, "process-serialization")
    body = b"one process owns this response"
    calls_path = tmp_path / "contacts.log"
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    _allow_contact(monkeypatch)

    class ForkResponse(_Response):
        def __init__(self):
            super().__init__(body)
            self.waited = False

        def read(self, size=-1):
            if not self.waited:
                self.waited = True
                os.write(ready_write, b"c")
                if os.read(release_read, 1) != b"x":
                    raise RuntimeError("parent did not release the process response")
            return super().read(size)

    def opened(request, _timeout, opener=None):
        fd = os.open(calls_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, f"{os.getpid()} {request.full_url}\n".encode())
        finally:
            os.close(fd)
        return 200, {}, ForkResponse()

    monkeypatch.setattr(fetch, "_open_no_follow", opened)

    def fork_acquirer(index: int) -> int:
        pid = os.fork()
        if pid != 0:
            return pid
        try:  # pragma: no cover - assertions remain in the parent
            os.close(ready_read)
            os.close(release_write)
            opened_run = store.Run.open(tmp_path, "acme.example", run.run_id)
            child_ctx = SimpleNamespace(run=opened_run, profile=ctx.profile, scope=ctx.scope)
            acquired = fetch.scoped_get_file(
                child_ctx, "https://t/process", dest, "t", chunk=7,
                governor=contract.DiskGovernor(reserve_bytes=0),
            )[0]
            result_path = tmp_path / f"process-result-{index}.json"
            result_path.write_text(json.dumps({
                "contacted": acquired.contacted,
                "disposition": acquired.disposition,
                "complete": acquired.complete,
            }))
        except BaseException as exc:
            (tmp_path / f"process-error-{index}.txt").write_text(
                f"{type(exc).__name__}: {exc}",
            )
            os._exit(70)
        os._exit(0)

    first = fork_acquirer(1)
    second = fork_acquirer(2)
    os.close(ready_write)
    os.close(release_read)
    statuses = []
    try:
        ready, _, _ = select.select([ready_read], [], [], 5)
        assert ready and os.read(ready_read, 1) == b"c"
        time.sleep(0.1)
        assert len(calls_path.read_text().splitlines()) == 1
        os.write(release_write, b"x")
        statuses = [_wait_child(first), _wait_child(second)]
    finally:
        for fd in (ready_read, release_write):
            try:
                os.close(fd)
            except OSError:
                pass
        if len(statuses) < 2:
            for pid in (first, second):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass

    errors = sorted(tmp_path.glob("process-error-*.txt"))
    assert all(os.waitstatus_to_exitcode(status) == 0 for status in statuses), [
        path.read_text() for path in errors
    ]
    assert len(calls_path.read_text().splitlines()) == 1
    results = [
        json.loads((tmp_path / f"process-result-{index}.json").read_text())
        for index in (1, 2)
    ]
    assert sorted((item["contacted"], item["disposition"]) for item in results) == [
        (False, "replayed-complete"), (True, "complete"),
    ]
    assert dest.read_bytes() == body


def test_crashed_destination_lease_refuses_without_a_second_contact(tmp_path, monkeypatch):
    ctx, run, dest = _running_context(tmp_path, "crashed-lease")
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    _allow_contact(monkeypatch)

    class NeverReleasedResponse(_Response):
        def read(self, size=-1):
            os.write(ready_write, b"c")
            os.read(release_read, 1)
            return super().read(size)

    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: (200, {}, NeverReleasedResponse(b"unsettled")),
    )
    child = os.fork()
    if child == 0:  # pragma: no cover - the parent owns assertions
        try:
            os.close(ready_read)
            os.close(release_write)
            opened_run = store.Run.open(tmp_path, "acme.example", run.run_id)
            child_ctx = SimpleNamespace(run=opened_run, profile=ctx.profile, scope=ctx.scope)
            fetch.scoped_get_file(
                child_ctx, "https://t/crash", dest, "t", chunk=8,
                governor=contract.DiskGovernor(reserve_bytes=0),
            )
        except BaseException:
            os._exit(70)
        os._exit(0)

    os.close(ready_write)
    os.close(release_read)
    try:
        ready, _, _ = select.select([ready_read], [], [], 5)
        assert ready and os.read(ready_read, 1) == b"c"
        os.kill(child, signal.SIGKILL)
        _wait_child(child)
    finally:
        os.close(ready_read)
        os.close(release_write)

    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("a crash-stale lease contacted the target"),
    )
    refused, final, status = fetch.scoped_get_file(
        ctx, "https://t/crash", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert refused is not None and refused.contacted is False and not refused.complete
    assert any(word in f"{refused.disposition} {refused.error}".lower()
               for word in ("stale", "unknown", "ownership", "lease"))
    assert (final, status) == ("https://t/crash", 0)
    assert not dest.exists() and not _receipt_path(dest).exists()


def test_substituted_destination_lease_neither_contacts_nor_publishes(tmp_path, monkeypatch):
    ctx, run, dest = _running_context(tmp_path, "substituted-lease")
    entered = threading.Event()
    release = threading.Event()
    calls: list[str] = []
    owner_errors: list[BaseException] = []
    owner_results: list[fetch.Acquisition] = []
    _allow_contact(monkeypatch)

    class BlockingResponse(_Response):
        def read(self, size=-1):
            entered.set()
            assert release.wait(5), "test did not release substituted lease owner"
            return super().read(size)

    def opened(request, _timeout, opener=None):
        calls.append(request.full_url)
        return 200, {}, BlockingResponse(b"must not publish")

    monkeypatch.setattr(fetch, "_open_no_follow", opened)

    def own():
        try:
            acquired, _final, _status = fetch.scoped_get_file(
                ctx, "https://t/substitute", dest, "t", chunk=8,
                governor=contract.DiskGovernor(reserve_bytes=0),
            )
            owner_results.append(acquired)
        except BaseException as exc:
            owner_errors.append(exc)

    owner = threading.Thread(target=own, daemon=True)
    owner.start()
    assert entered.wait(5)
    claim_dir = tmp_path / "recon" / "state" / "claims" / run.run_id
    markers = list(claim_dir.glob("*.claim"))
    assert len(markers) == 1
    marker = markers[0]
    marker.unlink()
    marker.write_text('{"substituted":true}')
    os.chmod(marker, 0o600)

    before = len(calls)
    contender_run = store.Run.open(tmp_path, "acme.example", run.run_id)
    contender_ctx = SimpleNamespace(run=contender_run, profile=ctx.profile, scope=ctx.scope)
    refused, _final, _status = fetch.scoped_get_file(
        contender_ctx, "https://t/substitute", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert len(calls) == before
    assert refused is not None and refused.contacted is False and not refused.complete

    release.set()
    owner.join(5)
    assert not owner.is_alive() and not owner_errors
    assert len(owner_results) == 1
    assert owner_results[0].contacted and not owner_results[0].complete
    assert owner_results[0].disposition == "managed-uncertain"
    assert not dest.exists() and not _receipt_path(dest).exists()
    assert marker.read_text() == '{"substituted":true}'


def test_distinct_managed_paths_may_contact_concurrently(tmp_path, monkeypatch):
    ctx, run, first_dest = _running_context(tmp_path, "distinct-concurrency")
    second_dest = run.raw_path("params", "managed", "other.bin")
    both_entered = threading.Event()
    release = threading.Event()
    guard = threading.Lock()
    entered: set[str] = set()
    errors: list[BaseException] = []
    _allow_contact(monkeypatch)

    class BlockingResponse(_Response):
        def __init__(self, url: str):
            super().__init__(url.encode("utf-8"))
            self.url = url

        def read(self, size=-1):
            with guard:
                entered.add(self.url)
                if len(entered) == 2:
                    both_entered.set()
            assert release.wait(5), "test did not release distinct responses"
            return super().read(size)

    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda request, _timeout, opener=None: (200, {}, BlockingResponse(request.full_url)),
    )

    def acquire(url, dest, opened_run):
        local = SimpleNamespace(run=opened_run, profile=ctx.profile, scope=ctx.scope)
        try:
            fetch.scoped_get_file(
                local, url, dest, "t", chunk=8,
                governor=contract.DiskGovernor(reserve_bytes=0),
            )
        except BaseException as exc:
            errors.append(exc)

    other = store.Run.open(tmp_path, "acme.example", run.run_id)
    workers = [
        threading.Thread(target=acquire, args=("https://t/one", first_dest, run)),
        threading.Thread(target=acquire, args=("https://t/two", second_dest, other)),
    ]
    for worker in workers:
        worker.start()
    assert both_entered.wait(2), "a run-global network lease serialized distinct destinations"
    release.set()
    for worker in workers:
        worker.join(5)

    assert not errors and all(not worker.is_alive() for worker in workers)
    assert first_dest.exists() and second_dest.exists()


def test_blocked_response_claim_makes_finalizer_refuse_immediately(tmp_path, monkeypatch):
    ctx, run, dest = _running_context(tmp_path, "claim-versus-seal")
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    errors: list[BaseException] = []
    _allow_contact(monkeypatch)

    class BlockingResponse(_Response):
        def read(self, size=-1):
            entered.set()
            assert release.wait(5), "test did not release blocked acquisition"
            return super().read(size)

    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: (200, {}, BlockingResponse(b"body")),
    )

    def acquire():
        try:
            fetch.scoped_get_file(
                ctx, "https://t/seal", dest, "t", chunk=8,
                governor=contract.DiskGovernor(reserve_bytes=0),
            )
        except BaseException as exc:
            errors.append(exc)
        finally:
            finished.set()

    worker = threading.Thread(target=acquire, daemon=True)
    worker.start()
    assert entered.wait(5)
    sealer = store.Run.open(tmp_path, "acme.example", run.run_id)
    started = time.monotonic()
    with pytest.raises(Exception, match="live artifact claim"):
        sealer.begin_finalization()
    elapsed = time.monotonic() - started
    assert elapsed < 0.5 and sealer.state == "running"

    release.set()
    assert finished.wait(5)
    worker.join(1)
    assert not errors and dest.read_bytes() == b"body"
    sealer.begin_finalization()
    assert sealer.state == "finalizing"


def test_prior_appearing_after_reconcile_is_never_overwritten(tmp_path, monkeypatch):
    ctx, _run, dest = _running_context(tmp_path, "prior-appears")
    prior = b"external prior must survive"
    body = b"newly acquired candidate"
    calls: list[str] = []
    _allow_contact(monkeypatch)

    class AppearingPrior(_Response):
        def read(self, size=-1):
            if not dest.exists():
                dest.write_bytes(prior)
            return super().read(size)

    def opened(request, _timeout, opener=None):
        calls.append(request.full_url)
        return 200, {}, AppearingPrior(body)

    monkeypatch.setattr(fetch, "_open_no_follow", opened)
    try:
        result = fetch.scoped_get_file(
            ctx, "https://t/prior", dest, "t", chunk=8,
            governor=contract.DiskGovernor(reserve_bytes=0),
        )[0]
    except Exception:
        result = None

    assert calls == ["https://t/prior"]
    assert dest.read_bytes() == prior
    if result is not None:
        assert result.disposition != "complete"


def test_receipt_appearing_after_reconcile_is_never_overwritten(tmp_path, monkeypatch):
    ctx, _run, dest = _running_context(tmp_path, "receipt-appears")
    planted_receipt = b'{"foreign":"receipt"}'
    body = b"response whose ownership name was taken"
    calls: list[str] = []
    _allow_contact(monkeypatch)

    class AppearingReceipt(_Response):
        def read(self, size=-1):
            receipt = _receipt_path(dest)
            if not receipt.exists():
                receipt.write_bytes(planted_receipt)
                os.chmod(receipt, 0o600)
            return super().read(size)

    def opened(request, _timeout, opener=None):
        calls.append(request.full_url)
        return 200, {}, AppearingReceipt(body)

    monkeypatch.setattr(fetch, "_open_no_follow", opened)
    acquired, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/receipt-prior", dest, "t", chunk=8,
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert calls == ["https://t/receipt-prior"]
    assert _receipt_path(dest).read_bytes() == planted_receipt
    assert acquired.disposition != "complete"
    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("foreign receipt triggered a second contact"),
    )
    refused, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/receipt-prior", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert refused.contacted is False and not refused.complete


def test_body_cas_committed_with_reported_fault_returns_reconciled_complete(
    tmp_path, monkeypatch,
):
    ctx, _run, dest = _running_context(tmp_path, "body-cas-reconciled")
    body = b"durable despite reported namespace fault"
    calls: list[str] = []
    _serve(monkeypatch, _Response(body), calls)
    real_fsync = os.fsync
    fired = False

    def fsync_then_report(fd):
        nonlocal fired
        if (_fd_target(fd) == str(dest.parent) and dest.exists()
                and not _receipt_path(dest).exists() and not fired):
            fired = True
            real_fsync(fd)
            raise OSError("body namespace fsync reported after commit")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync_then_report)
    acquired, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/body-cas", dest, "t", chunk=8,
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert fired and calls == ["https://t/body-cas"]
    assert acquired.complete and acquired.disposition == "complete"
    assert "fsync" in (acquired.error or "").lower()
    assert dest.read_bytes() == body and _receipt_path(dest).exists()

    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("reconciled body was requested twice"),
    )
    replay, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/body-cas", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert replay.complete and replay.disposition == "replayed-complete"


def test_body_cas_with_unsettled_directory_durability_is_never_complete(
    tmp_path, monkeypatch,
):
    ctx, _run, dest = _running_context(tmp_path, "body-cas-uncertain")
    body = b"landed name without proven directory durability"
    calls: list[str] = []
    _serve(monkeypatch, _Response(body), calls)
    real_fsync = os.fsync
    faults = 0

    def refuse_body_directory_fsync(fd):
        nonlocal faults
        if (_fd_target(fd) == str(dest.parent) and dest.exists()
                and not _receipt_path(dest).exists()):
            faults += 1
            raise OSError("body directory durability unavailable")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", refuse_body_directory_fsync)
    acquired, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/body-uncertain", dest, "t", chunk=8,
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert faults and calls == ["https://t/body-uncertain"]
    assert acquired.contacted is True and not acquired.complete
    assert "uncertain" in f"{acquired.disposition} {acquired.error}".lower()
    assert not _receipt_path(dest).exists()

    monkeypatch.setattr(os, "fsync", real_fsync)
    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("uncertain publication was requested twice"),
    )
    refused, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/body-uncertain", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert refused.contacted is False and not refused.complete


def test_receipt_write_failure_reports_complete_unowned_and_replays_as_refusal(
    tmp_path, monkeypatch,
):
    ctx, _run, dest = _running_context(tmp_path, "receipt-write-failure")
    body = b"whole body whose receipt cannot be staged"
    calls: list[str] = []
    _serve(monkeypatch, _Response(body), calls)
    real_write = os.write
    fired = False

    def fail_receipt_stage(fd, data):
        nonlocal fired
        target = _fd_target(fd)
        if (dest.exists() and not _receipt_path(dest).exists()
                and target.endswith(".stage") and not fired):
            fired = True
            raise OSError("receipt stage is unwritable")
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", fail_receipt_stage)
    acquired, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/receipt-write", dest, "t", chunk=8,
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert fired and not acquired.complete and acquired.path is None
    assert acquired.partial is None and acquired.disposition == "complete-unowned"
    assert dest.read_bytes() == body and not _receipt_path(dest).exists()
    monkeypatch.setattr(os, "write", real_write)
    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("unowned whole body was requested twice"),
    )
    refused, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/receipt-write", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    # The post-contact failure retains the deterministic marker.  A replay is
    # denied before an opaque transaction can yield, so it cannot safely infer
    # the body-only namespace state as ``orphan-complete`` through ambient I/O.
    assert refused.contacted is False
    assert refused.disposition == "managed-authority-refused"


@pytest.mark.parametrize("mutation", ["body-replace", "body-unlink"])
def test_receipt_failure_never_exposes_an_uncertified_body_path(
    tmp_path, monkeypatch, mutation,
):
    ctx, run, dest = _running_context(tmp_path, f"receipt-failure-{mutation}")
    body = b"original body before companion publication fault"
    calls: list[str] = []
    _serve(monkeypatch, _Response(body), calls)
    real_publish = store._ManagedAcquisitionTransaction.publish_companion_if_absent
    fired = False

    def mutate_then_fail(transaction, components, data):
        nonlocal fired
        if not fired:
            fired = True
            if mutation == "body-replace":
                planted = dest.with_name(dest.name + ".foreign")
                planted.write_bytes(b"foreign body after body snapshot")
                os.chmod(planted, 0o600)
                os.replace(planted, dest)
            else:
                dest.unlink()
            raise OSError("companion publication refused after body mutation")
        return real_publish(transaction, components, data)

    monkeypatch.setattr(
        store._ManagedAcquisitionTransaction,
        "publish_companion_if_absent", mutate_then_fail,
    )
    acquired, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/receipt-body-change", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert fired and calls == ["https://t/receipt-body-change"]
    assert acquired.contacted is True and not acquired.complete
    assert acquired.path is None and acquired.partial is None
    assert acquired.disposition == "complete-unowned"
    assert evidence._text_of(acquired) is None
    claim_dir = tmp_path / "recon" / "state" / "claims" / run.run_id
    assert len(list(claim_dir.glob("*.claim"))) == 1

    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("unowned body was requested twice"),
    )
    refused, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/receipt-body-change", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert refused.contacted is False and not refused.complete


@pytest.mark.parametrize("selected", ["complete", "partial"])
@pytest.mark.parametrize("boundary", ["body-cas", "certificate", "release"])
def test_terminal_acquisition_requires_the_opposite_body_name_to_remain_absent(
    tmp_path, monkeypatch, selected, boundary,
):
    ctx, run, dest = _running_context(
        tmp_path, f"terminal-triad-{selected}-{boundary}",
    )
    prefix = b"body bytes whose opposite sibling must stay absent"
    response = (
        _Response(prefix)
        if selected == "complete"
        else _PrefixThenCancel(prefix, OSError("broken response after prefix"))
    )
    calls: list[str] = []
    _serve(monkeypatch, response, calls)
    sibling = (
        dest.with_name(dest.name + ".part")
        if selected == "complete"
        else dest
    )
    real_publish = store._ManagedAcquisitionTransaction.publish_body_if_absent
    real_certify = store._ManagedAcquisitionTransaction.certify_pair
    real_release = store._ManagedPairRelease._delete_quarantine_locked
    fired = False

    def plant_sibling():
        nonlocal fired
        if not fired:
            fired = True
            sibling.write_bytes(b"foreign mutually exclusive body sibling")
            sibling.chmod(0o600)

    def publish_after_conflict(transaction, *args, **kwargs):
        plant_sibling()
        return real_publish(transaction, *args, **kwargs)

    def certify_after_conflict(transaction, *args, **kwargs):
        plant_sibling()
        return real_certify(transaction, *args, **kwargs)

    def release_after_conflict(owner):
        plant_sibling()
        return real_release(owner)

    with monkeypatch.context() as patch:
        if boundary == "body-cas":
            patch.setattr(
                store._ManagedAcquisitionTransaction,
                "publish_body_if_absent", publish_after_conflict,
            )
        elif boundary == "certificate":
            patch.setattr(
                store._ManagedAcquisitionTransaction,
                "certify_pair", certify_after_conflict,
            )
        else:
            patch.setattr(
                store._ManagedPairRelease,
                "_delete_quarantine_locked", release_after_conflict,
            )
        acquired, _final, _status = fetch.scoped_get_file(
            ctx, "https://t/terminal-triad", dest, "t",
            governor=contract.DiskGovernor(reserve_bytes=0),
        )

    assert fired and calls == ["https://t/terminal-triad"]
    assert acquired.contacted is True and not acquired.complete
    assert acquired.path is None and acquired.partial is None
    assert acquired.disposition == "managed-uncertain"
    assert sibling.read_bytes() == b"foreign mutually exclusive body sibling"
    claim_dir = tmp_path / "recon" / "state" / "claims" / run.run_id
    assert len(list(claim_dir.glob("*.claim"))) == 1

    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("uncertified triad recontacted provider"),
    )
    replay, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/terminal-triad", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert replay.contacted is False and not replay.complete
    assert replay.path is None and replay.partial is None
    assert replay.disposition == "managed-authority-refused"


def test_receipt_cas_committed_with_reported_fault_is_owned_before_return(
    tmp_path, monkeypatch,
):
    ctx, _run, dest = _running_context(tmp_path, "receipt-cas-reconciled")
    body = b"body and receipt both settle"
    calls: list[str] = []
    _serve(monkeypatch, _Response(body), calls)
    real_fsync = os.fsync
    fired = False

    def receipt_fsync_then_report(fd):
        nonlocal fired
        if (_fd_target(fd) == str(dest.parent) and _receipt_path(dest).exists()
                and not fired):
            fired = True
            real_fsync(fd)
            raise OSError("receipt namespace fsync reported after commit")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", receipt_fsync_then_report)
    acquired, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/receipt-cas", dest, "t", chunk=8,
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert fired and acquired.complete and acquired.disposition == "complete"
    assert "receipt" in (acquired.error or "").lower()
    assert dest.read_bytes() == body and _receipt_path(dest).exists()
    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("committed receipt was requested twice"),
    )
    replay, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/receipt-cas", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert replay.complete and replay.disposition == "replayed-complete"


def test_terminal_claim_exit_fault_is_diagnostic_for_fresh_and_replay(
    tmp_path, monkeypatch,
):
    ctx, _run, dest = _running_context(tmp_path, "terminal-exit-fault")
    body = b"body and receipt are terminal before the wrapper reports"
    calls: list[str] = []
    _serve(monkeypatch, _Response(body), calls)
    real_claim = store.Run.managed_acquisition_claim

    @contextlib.contextmanager
    def report_after_terminal_release(run, *components):
        with real_claim(run, *components) as transaction:
            yield transaction
        raise OSError("claim exit reported after terminal release")

    monkeypatch.setattr(
        store.Run, "managed_acquisition_claim", report_after_terminal_release,
    )
    acquired, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/terminal-exit", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert calls == ["https://t/terminal-exit"]
    assert acquired.complete and acquired.disposition == "complete"
    assert "claim exit reported after terminal release" in acquired.error
    assert dest.read_bytes() == body and _receipt_path(dest).exists()

    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("terminal pair was requested twice"),
    )
    replay, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/terminal-exit", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert replay.complete and replay.disposition == "replayed-complete"
    assert "claim exit reported after terminal release" in replay.error


@pytest.mark.parametrize("outcome", ["budget", "first-hop-guard", "orphan"])
def test_clean_precontact_result_survives_reported_claim_exit_fault(
    tmp_path, monkeypatch, outcome,
):
    ctx, run, dest = _running_context(tmp_path, f"precontact-exit-{outcome}")
    url = "https://t/precontact-exit"
    calls: list[str] = []
    governor = contract.DiskGovernor(reserve_bytes=0)
    if outcome == "budget":
        governor = contract.DiskGovernor(
            run_max=1, run_streamed=1, reserve_bytes=0,
        )
        _serve(monkeypatch, _Response(b"must not contact"), calls)
    elif outcome == "first-hop-guard":
        monkeypatch.setattr(
            fetch.netguard, "contact_state",
            lambda *_args, **_kwargs: ("blocked", None, None),
        )
        monkeypatch.setattr(
            fetch, "_open_no_follow",
            lambda *_args, **_kwargs: pytest.fail("guarded hop was contacted"),
        )
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"unowned prior")
        os.chmod(dest, 0o600)
        _serve(monkeypatch, _Response(b"must not contact"), calls)

    real_claim = store.Run.managed_acquisition_claim

    @contextlib.contextmanager
    def report_after_clean_release(owner, *components):
        with real_claim(owner, *components) as transaction:
            yield transaction
        raise OSError("claim exit reported after clean precontact release")

    monkeypatch.setattr(
        store.Run, "managed_acquisition_claim", report_after_clean_release,
    )
    acquired, final, status = fetch.scoped_get_file(
        ctx, url, dest, "t", governor=governor,
    )

    assert calls == [] and (final, status) == (url, 0)
    if outcome == "first-hop-guard":
        assert acquired is None
    else:
        assert acquired is not None and acquired.contacted is False
        assert not acquired.complete
        assert "claim exit reported after clean precontact release" in acquired.error
        expected = "budget-exhausted" if outcome == "budget" else "orphan-complete"
        assert acquired.disposition == expected
    claim_dir = tmp_path / "recon" / "state" / "claims" / run.run_id
    assert list(claim_dir.glob("*.claim")) == []


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_exact_terminal_claim_exit_cancellation_is_preserved(
    tmp_path, monkeypatch, cancellation_type,
):
    ctx, _run, dest = _running_context(
        tmp_path, f"terminal-exit-{cancellation_type.__name__}",
    )
    body = b"terminal bytes survive an exact wrapper cancellation"
    calls: list[str] = []
    _serve(monkeypatch, _Response(body), calls)
    real_claim = store.Run.managed_acquisition_claim
    cancellation = cancellation_type("exact claim-exit cancellation")

    @contextlib.contextmanager
    def cancel_after_terminal_release(run, *components):
        with real_claim(run, *components) as transaction:
            yield transaction
        raise cancellation

    monkeypatch.setattr(
        store.Run, "managed_acquisition_claim", cancel_after_terminal_release,
    )
    with pytest.raises(cancellation_type) as caught:
        fetch.scoped_get_file(
            ctx, "https://t/terminal-cancel", dest, "t",
            governor=contract.DiskGovernor(reserve_bytes=0),
        )

    assert caught.value is cancellation
    assert calls == ["https://t/terminal-cancel"]
    assert dest.read_bytes() == body and _receipt_path(dest).exists()


def test_invalid_utf8_managed_receipt_is_damaged_and_never_recontacted(
    tmp_path, monkeypatch,
):
    ctx, _run, dest = _running_context(tmp_path, "receipt-invalid-utf8")
    body = b"body with a receipt that will be corrupted"
    calls: list[str] = []
    _serve(monkeypatch, _Response(body), calls)
    acquired, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/invalid-utf8", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert acquired.complete

    receipt = _receipt_path(dest)
    encoded = receipt.read_bytes()
    marker = b"https://t/invalid-utf8"
    offset = encoded.index(marker)
    receipt.write_bytes(encoded[:offset] + b"\xff" + encoded[offset + 1:])
    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("damaged receipt was requested twice"),
    )

    replay, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/invalid-utf8", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert calls == ["https://t/invalid-utf8"]
    assert replay.contacted is False and not replay.complete
    assert replay.disposition == "receipt-damaged"
    assert "UTF-8" in replay.error


@pytest.mark.parametrize("mutation", ["receipt-unlink", "body-replace"])
def test_final_pair_certification_failure_never_returns_complete_or_recontacts(
    tmp_path, monkeypatch, mutation,
):
    ctx, run, dest = _running_context(tmp_path, f"pair-current-{mutation}")
    body = b"body whose final pair must remain current"
    calls: list[str] = []
    _serve(monkeypatch, _Response(body), calls)
    real_claim = store.Run.managed_acquisition_claim
    fired = False

    class SnapshotMutator:
        def __init__(self, transaction):
            self.transaction = transaction

        def __getattr__(self, name):
            return getattr(self.transaction, name)

        def snapshot(self, components, **kwargs):
            nonlocal fired
            snapshot = self.transaction.snapshot(components, **kwargs)
            if (not fired and snapshot is not None and dest.exists()
                    and components[-1].endswith(fetch._RECEIPT_SUFFIX)):
                fired = True
                if mutation == "receipt-unlink":
                    _receipt_path(dest).unlink()
                else:
                    dest.write_bytes(b"foreign replacement after the body snapshot")
            return snapshot

    @contextlib.contextmanager
    def mutate_after_final_snapshot(owner, *components):
        with real_claim(owner, *components) as transaction:
            yield SnapshotMutator(transaction)

    monkeypatch.setattr(
        store.Run, "managed_acquisition_claim", mutate_after_final_snapshot,
    )
    acquired, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/current-pair", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert fired and calls == ["https://t/current-pair"]
    assert acquired.contacted is True and not acquired.complete
    assert acquired.path is None and acquired.disposition == "managed-uncertain"
    claim_dir = tmp_path / "recon" / "state" / "claims" / run.run_id
    assert len(list(claim_dir.glob("*.claim"))) == 1

    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("uncertified pair was requested twice"),
    )
    refused, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/current-pair", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert refused.contacted is False and not refused.complete
    assert refused.disposition == "managed-authority-refused"


@pytest.mark.parametrize("mutation", ["receipt-unlink", "body-replace"])
def test_replay_pair_change_after_snapshot_refuses_without_claiming_complete(
    tmp_path, monkeypatch, mutation,
):
    ctx, run, dest = _running_context(tmp_path, f"replay-current-{mutation}")
    body = b"original certified replay body"
    calls: list[str] = []
    _serve(monkeypatch, _Response(body), calls)
    acquired, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/replay-current", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert acquired.complete

    real_claim = store.Run.managed_acquisition_claim
    fired = False

    class ReplayMutator:
        def __init__(self, transaction):
            self.transaction = transaction

        def __getattr__(self, name):
            return getattr(self.transaction, name)

        def snapshot(self, components, **kwargs):
            nonlocal fired
            snapshot = self.transaction.snapshot(components, **kwargs)
            at_boundary = (
                mutation == "receipt-unlink"
                and components[-1].endswith(fetch._RECEIPT_SUFFIX)
                or mutation == "body-replace" and tuple(components)
                == tuple(self.transaction.components)
            )
            if not fired and snapshot is not None and at_boundary:
                fired = True
                if mutation == "receipt-unlink":
                    _receipt_path(dest).unlink()
                else:
                    dest.write_bytes(b"foreign bytes after replay snapshot")
            return snapshot

    @contextlib.contextmanager
    def mutate_replay(owner, *components):
        with real_claim(owner, *components) as transaction:
            yield ReplayMutator(transaction)

    monkeypatch.setattr(store.Run, "managed_acquisition_claim", mutate_replay)
    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("replay currentness contacted provider"),
    )
    replay, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/replay-current", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert fired and calls == ["https://t/replay-current"]
    assert replay.contacted is False and not replay.complete
    assert replay.path is None and replay.disposition == "managed-authority-refused"
    claim_dir = tmp_path / "recon" / "state" / "claims" / run.run_id
    assert len(list(claim_dir.glob("*.claim"))) == 1


def test_opener_escape_after_attempt_is_uncertain_and_never_recontacted(
    tmp_path, monkeypatch,
):
    ctx, run, dest = _running_context(tmp_path, "opener-uncertain")
    calls: list[str] = []
    _allow_contact(monkeypatch)

    def uncertain_open(request, _timeout, opener=None):
        calls.append(request.full_url)
        raise TimeoutError("the opener may have contacted the provider")

    monkeypatch.setattr(fetch, "_open_no_follow", uncertain_open)
    acquired, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/opener", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert calls == ["https://t/opener"]
    assert acquired.contacted is True and not acquired.complete
    assert acquired.path is None and acquired.disposition == "managed-uncertain"
    claim_dir = tmp_path / "recon" / "state" / "claims" / run.run_id
    assert len(list(claim_dir.glob("*.claim"))) == 1

    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("uncertain opener was invoked twice"),
    )
    refused, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/opener", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert refused.contacted is False and not refused.complete


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_exact_opener_cancellation_is_preserved_after_retaining_attempt(
    tmp_path, monkeypatch, cancellation_type,
):
    ctx, run, dest = _running_context(
        tmp_path, f"opener-{cancellation_type.__name__}",
    )
    cancellation = cancellation_type("exact opener cancellation")
    _allow_contact(monkeypatch)
    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(cancellation),
    )

    with pytest.raises(cancellation_type) as caught:
        fetch.scoped_get_file(
            ctx, "https://t/opener-cancel", dest, "t",
            governor=contract.DiskGovernor(reserve_bytes=0),
        )

    assert caught.value is cancellation
    claim_dir = tmp_path / "recon" / "state" / "claims" / run.run_id
    assert len(list(claim_dir.glob("*.claim"))) == 1


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_exact_pacing_cancellation_is_preserved_before_opener(
    tmp_path, monkeypatch, cancellation_type,
):
    ctx, run, dest = _running_context(
        tmp_path, f"pace-{cancellation_type.__name__}",
    )
    ctx.profile.http_rl = 1
    cancellation = cancellation_type("exact pacing cancellation")
    _allow_contact(monkeypatch)
    monkeypatch.setattr(
        fetch.time, "sleep", lambda *_args, **_kwargs: (_ for _ in ()).throw(cancellation),
    )
    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("pacing cancellation reached opener"),
    )

    with pytest.raises(cancellation_type) as caught:
        fetch.scoped_get_file(
            ctx, "https://t/pace-cancel", dest, "t",
            governor=contract.DiskGovernor(reserve_bytes=0),
        )

    assert caught.value is cancellation
    assert not dest.exists() and not _receipt_path(dest).exists()
    claim_dir = tmp_path / "recon" / "state" / "claims" / run.run_id
    assert len(list(claim_dir.glob("*.claim"))) == 1


def test_out_of_scope_redirect_after_contact_is_uncertain_not_uncontacted(
    tmp_path, monkeypatch,
):
    ctx, run, dest = _running_context(tmp_path, "redirect-uncertain")
    ctx.scope.active_allowed = lambda host: host == "t"
    calls: list[str] = []
    _allow_contact(monkeypatch)

    def redirected(request, _timeout, opener=None):
        calls.append(request.full_url)
        return 302, {"Location": "https://elsewhere.test/body"}, _Response(b"")

    monkeypatch.setattr(fetch, "_open_no_follow", redirected)
    acquired, final, status = fetch.scoped_get_file(
        ctx, "https://t/redirect", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert calls == ["https://t/redirect"]
    assert acquired.contacted is True and not acquired.complete
    assert acquired.path is None and acquired.disposition == "managed-uncertain"
    assert (final, status) == ("https://elsewhere.test/body", 302)
    claim_dir = tmp_path / "recon" / "state" / "claims" / run.run_id
    assert len(list(claim_dir.glob("*.claim"))) == 1


@pytest.mark.parametrize(("malformed", "value"), [
    ("status", "200"),
    ("status", True),
    ("status", 700),
    ("status", -1),
    ("status", None),
    ("headers", None),
    ("headers", True),
    ("headers", object()),
    ("location", b"https://elsewhere.test/body"),
    ("location", 7),
    ("response", None),
])
def test_malformed_opened_response_is_uncertain_and_never_published(
    tmp_path, monkeypatch, malformed, value,
):
    ctx, run, dest = _running_context(
        tmp_path, f"malformed-{malformed}-{type(value).__name__}",
    )
    calls: list[str] = []
    _allow_contact(monkeypatch)

    def opened(request, _timeout, opener=None):
        calls.append(request.full_url)
        status, headers, response = 200, {}, _Response(b"must not publish")
        if malformed == "status":
            status = value
        elif malformed == "headers":
            headers = value
        elif malformed == "location":
            status, headers = 302, {"Location": value}
        else:
            response = value
        return status, headers, response

    monkeypatch.setattr(fetch, "_open_no_follow", opened)
    acquired, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/malformed", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )

    assert calls == ["https://t/malformed"]
    assert acquired.contacted is True and not acquired.complete
    assert acquired.path is None and acquired.disposition == "managed-uncertain"
    assert not dest.exists() and not _receipt_path(dest).exists()
    claim_dir = tmp_path / "recon" / "state" / "claims" / run.run_id
    assert len(list(claim_dir.glob("*.claim"))) == 1

    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("malformed response was requested twice"),
    )
    refused, _final, _status = fetch.scoped_get_file(
        ctx, "https://t/malformed", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert refused.contacted is False and not refused.complete


@pytest.mark.parametrize("boundary", ["body", "receipt"])
@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_exact_namespace_cancellation_settles_ownership_before_propagation(
    tmp_path, monkeypatch, boundary, cancellation_type,
):
    ctx, run, dest = _running_context(
        tmp_path, f"namespace-{boundary}-{cancellation_type.__name__}",
    )
    body = b"terminal namespace cancellation body"
    calls: list[str] = []
    _serve(monkeypatch, _Response(body), calls)
    real_fsync = os.fsync
    cancellation = cancellation_type(f"exact {boundary} namespace cancellation")
    fired = False

    def cancel_after_namespace_fsync(fd):
        nonlocal fired
        receipt_exists = _receipt_path(dest).exists()
        at_boundary = (
            dest.exists()
            and ((boundary == "body" and not receipt_exists)
                 or (boundary == "receipt" and receipt_exists))
            and _fd_target(fd) == str(dest.parent)
        )
        if at_boundary and not fired:
            fired = True
            real_fsync(fd)
            raise cancellation
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", cancel_after_namespace_fsync)
    with pytest.raises(cancellation_type) as caught:
        fetch.scoped_get_file(
            ctx, f"https://t/{boundary}-cancel", dest, "t", chunk=8,
            governor=contract.DiskGovernor(reserve_bytes=0),
        )

    assert fired and caught.value is cancellation
    assert calls == [f"https://t/{boundary}-cancel"]
    assert dest.read_bytes() == body and _receipt_path(dest).exists()
    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("settled cancellation was requested twice"),
    )
    replay, _final, _status = fetch.scoped_get_file(
        ctx, f"https://t/{boundary}-cancel", dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert replay.complete and replay.disposition == "replayed-complete"
    run.begin_finalization()  # public proof that no acquisition claim leaked


def test_probe_discard_ledger_distinguishes_removed_body_from_absent_receipt(
    tmp_path, monkeypatch,
):
    ctx, run, _dest = _running_context(tmp_path, "discard-removed-absent")
    calls: list[str] = []
    _serve(monkeypatch, _Response(b"not an SSTI hit"), calls)
    captured: list[Path] = []

    def classify(path):
        body = Path(path)
        captured.append(body)
        _receipt_path(body).unlink()
        return False

    monkeypatch.setattr(evidence, "_ssti_hit", classify)
    events.reset(); events.configure(run)
    try:
        assert evidence.probe_ssti(ctx, ["https://t/p?a=1"]) == 0
    finally:
        events.reset()

    assert len(calls) == 1 and len(captured) == 1
    assert not captured[0].exists() and not _receipt_path(captured[0]).exists()


def test_probe_discard_preserves_a_body_changed_after_acquisition(tmp_path, monkeypatch):
    ctx, run, _dest = _running_context(tmp_path, "discard-changed")
    calls: list[str] = []
    _serve(monkeypatch, _Response(b"owned response"), calls)
    changed = b"foreign replacement after classification"
    captured: list[Path] = []

    def substitute(path):
        body = Path(path)
        captured.append(body)
        planted = body.with_name(body.name + ".foreign")
        planted.write_bytes(changed)
        os.chmod(planted, 0o600)
        os.replace(planted, body)
        return False

    monkeypatch.setattr(evidence, "_ssti_hit", substitute)
    events.reset(); events.configure(run)
    try:
        assert evidence.probe_ssti(ctx, ["https://t/p?a=1"]) == 0
    finally:
        events.reset()

    assert captured[0].read_bytes() == changed
    diagnostic = _run_diagnostics(run)
    assert "discard" in diagnostic and "changed" in diagnostic


def test_probe_discard_reconciles_unlink_committed_with_reported_fault(
    tmp_path, monkeypatch,
):
    ctx, run, _dest = _running_context(tmp_path, "discard-committed-fault")
    _serve(monkeypatch, _Response(b"not an SSTI hit"), [])
    body_path: Path | None = None
    real_unlink = os.unlink
    fired = False

    def classify(path):
        nonlocal body_path
        body_path = Path(path)
        return False

    def unlink_then_report(path, *, dir_fd=None):
        nonlocal fired
        target = _unlink_target(path, dir_fd)
        if body_path is not None and target == body_path and not fired:
            fired = True
            real_unlink(path, dir_fd=dir_fd)
            raise OSError("body unlink reported after commit")
        return real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(evidence, "_ssti_hit", classify)
    monkeypatch.setattr(os, "unlink", unlink_then_report)
    events.reset(); events.configure(run)
    try:
        assert evidence.probe_ssti(ctx, ["https://t/p?a=1"]) == 0
    finally:
        events.reset()

    assert fired and body_path is not None
    assert not body_path.exists() and not _receipt_path(body_path).exists()


def test_probe_discard_reports_an_object_whose_unlink_never_committed(
    tmp_path, monkeypatch,
):
    ctx, run, _dest = _running_context(tmp_path, "discard-unremoved")
    _serve(monkeypatch, _Response(b"not an SSTI hit"), [])
    body_path: Path | None = None
    real_unlink = os.unlink
    faults = 0

    def classify(path):
        nonlocal body_path
        body_path = Path(path)
        return False

    def refuse_body_unlink(path, *, dir_fd=None):
        nonlocal faults
        target = _unlink_target(path, dir_fd)
        if body_path is not None and target == body_path:
            faults += 1
            raise OSError("body unlink did not commit")
        return real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(evidence, "_ssti_hit", classify)
    monkeypatch.setattr(os, "unlink", refuse_body_unlink)
    events.reset(); events.configure(run)
    try:
        assert evidence.probe_ssti(ctx, ["https://t/p?a=1"]) == 0
    finally:
        events.reset()

    assert faults and body_path is not None and body_path.exists()
    diagnostic = _run_diagnostics(run)
    assert "discard" in diagnostic
    assert any(word in diagnostic for word in ("unremoved", "uncertain", "failed"))


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_exact_discard_cancellation_settles_each_named_object_before_propagating(
    tmp_path, monkeypatch, cancellation_type,
):
    ctx, run, _dest = _running_context(
        tmp_path, f"discard-cancel-{cancellation_type.__name__}",
    )
    _serve(monkeypatch, _Response(b"not an SSTI hit"), [])
    body_path: Path | None = None
    real_unlink = os.unlink
    cancellation = cancellation_type("exact discard namespace cancellation")
    fired = False

    def classify(path):
        nonlocal body_path
        body_path = Path(path)
        return False

    def cancel_after_body_unlink(path, *, dir_fd=None):
        nonlocal fired
        target = _unlink_target(path, dir_fd)
        if body_path is not None and target == body_path and not fired:
            fired = True
            real_unlink(path, dir_fd=dir_fd)
            raise cancellation
        return real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(evidence, "_ssti_hit", classify)
    monkeypatch.setattr(os, "unlink", cancel_after_body_unlink)
    events.reset(); events.configure(run)
    try:
        with pytest.raises(cancellation_type) as caught:
            evidence.probe_ssti(ctx, ["https://t/p?a=1"])
    finally:
        events.reset()

    assert fired and caught.value is cancellation and body_path is not None
    assert not body_path.exists() and not _receipt_path(body_path).exists()
    run.begin_finalization()  # public proof that no acquisition claim leaked


def _fresh_managed_acquisition(ctx, dest, monkeypatch, *, url):
    calls: list[str] = []
    _serve(monkeypatch, _Response(b"discard wrapper body"), calls)
    acquired, _final, _status = fetch.scoped_get_file(
        ctx, url, dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert acquired.complete and calls == [url]
    return acquired


@pytest.mark.parametrize(
    "diagnostic",
    ["path-collision", "orphan-complete", "receipt-damaged", "ownership-conflict"],
)
def test_diagnostic_managed_snapshots_never_authorize_discard(
    tmp_path, monkeypatch, diagnostic,
):
    ctx, _run, dest = _running_context(
        tmp_path, f"discard-diagnostic-{diagnostic}",
    )
    original_url = "https://t/discard-owned-original"
    requested_url = original_url
    if diagnostic == "orphan-complete":
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"unowned orphan body")
        dest.chmod(0o600)
    else:
        owned = _fresh_managed_acquisition(
            ctx, dest, monkeypatch, url=original_url,
        )
        assert owned._managed_discard_certified
        if diagnostic == "path-collision":
            # A valid receipt for another acquisition remains foreign even if
            # its body is already gone; diagnostic visibility is not a delete
            # capability for that receipt.
            dest.unlink()
            requested_url = "https://t/discard-foreign-request"
        elif diagnostic == "receipt-damaged":
            _receipt_path(dest).write_bytes(b"not a valid receipt")
        elif diagnostic == "ownership-conflict":
            part = dest.with_name(dest.name + ".part")
            part.write_bytes(b"unowned conflicting partial")
            part.chmod(0o600)

    monkeypatch.setattr(
        fetch, "_open_no_follow",
        lambda *_args, **_kwargs: pytest.fail("diagnostic prior contacted provider"),
    )
    refused, _final, _status = fetch.scoped_get_file(
        ctx, requested_url, dest, "t",
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert refused.disposition == diagnostic
    assert refused.contacted is False and not refused._managed_discard_certified
    assert refused._managed_body_snapshot is None
    assert refused._managed_receipt_snapshot is None
    before = {
        path: path.read_bytes()
        for path in (
            dest,
            dest.with_name(dest.name + ".part"),
            _receipt_path(dest),
        )
        if path.exists()
    }

    with pytest.raises(fetch.AcquisitionRefused, match="certified owned"):
        fetch.discard_acquisition(ctx, refused)

    assert before
    assert {
        path: path.read_bytes()
        for path in before
        if path.exists()
    } == before


def _discard_wrapper_events(ctx, acquisition):
    events = []

    def trace(frame, event, _arg):
        if frame.f_code is fetch.discard_acquisition.__code__ and event == "line":
            events.append(frame.f_lineno)
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        ledger = fetch.discard_acquisition(ctx, acquisition)
    finally:
        sys.settrace(previous)
    assert ledger["body"].state.startswith("removed")
    assert ledger["receipt"].state.startswith("removed")
    return events


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_each_discard_wrapper_line_preserves_exact_truth_and_no_marker(
    tmp_path, monkeypatch, cancellation_type,
):
    probe_ctx, _probe_run, probe_dest = _running_context(
        tmp_path / "probe", "discard-wrapper-probe",
    )
    probe_acquisition = _fresh_managed_acquisition(
        probe_ctx, probe_dest, monkeypatch,
        url="https://t/discard-wrapper-probe",
    )
    events = _discard_wrapper_events(probe_ctx, probe_acquisition)
    assert events

    for target in range(1, len(events) + 1):
        case = tmp_path / f"{cancellation_type.__name__}-{target}"
        ctx, run, dest = _running_context(case, f"discard-wrapper-{target}")
        acquired = _fresh_managed_acquisition(
            ctx, dest, monkeypatch,
            url=f"https://t/discard-wrapper/{target}",
        )
        before_body = dest.read_bytes()
        before_receipt = _receipt_path(dest).read_bytes()
        cancellation = cancellation_type(
            f"discard wrapper occurrence {target}",
        )
        occurrence = 0
        fired = False

        def trace(frame, event, _arg):
            nonlocal occurrence, fired
            if frame.f_code is fetch.discard_acquisition.__code__ and event == "line":
                occurrence += 1
                if occurrence == target and not fired:
                    fired = True
                    sys.settrace(None)
                    raise cancellation
            return trace

        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            with pytest.raises(cancellation_type) as caught:
                fetch.discard_acquisition(ctx, acquired)
        finally:
            sys.settrace(previous)

        assert fired and caught.value is cancellation, (target, events[target - 1])
        claim_dir = case / "recon" / "state" / "claims" / run.run_id
        assert list(claim_dir.glob("*.claim")) == [], (target, events[target - 1])
        ledger = getattr(cancellation, "managed_discard", None)
        if ledger is None:
            # Before the opaque discard call begins, the pre-armed claim proves
            # no namespace effect.  At the finite post-discard wrapper reserve,
            # both names are already terminal even if no Python attachment can
            # be made to the newly injected cancellation.
            if dest.exists() or _receipt_path(dest).exists():
                assert dest.read_bytes() == before_body, (target, events[target - 1])
                assert _receipt_path(dest).read_bytes() == before_receipt
            else:
                assert not dest.exists() and not _receipt_path(dest).exists()
        else:
            assert type(ledger) is store.ManagedDiscardLedger
            assert ledger.body.state.startswith("removed")
            assert ledger.receipt.state.startswith("removed")
            assert not dest.exists() and not _receipt_path(dest).exists()
