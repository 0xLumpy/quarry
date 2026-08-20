"""Focused runner-owned seccomp listener bootstrap seams."""
from __future__ import annotations

import os
import time
from types import SimpleNamespace

import pytest

from quarry_recon import runner_ipc, runner_protocol as protocol, runner_worker
from quarry_recon.network_broker import ListenerHandoff, NetworkBrokerRefused
from quarry_recon.network_policy import PRIVATE_POLICY_ENV


pytestmark = pytest.mark.offline


def _request(*, environment=()):
    return protocol.normalize_invocation(
        request_id="ab" * 16,
        tool="fixture",
        cmd=("/bin/true",),
        timeout=3,
        env=dict(environment),
        base_environment={},
        raw_path="/tmp/runner-broker.stdout",
        stderr_path="/tmp/runner-broker.stderr",
    ).worker


def _closed(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError:
        return True
    return False


def test_release_callback_runs_after_the_exact_request_eof_and_before_exec_status_wait():
    release_read, release_write = os.pipe()
    status_read, status_write = os.pipe()
    report_read, report_write = os.pipe()
    ack_read, ack_write = os.pipe()
    events = []
    request = _request()
    launcher = runner_worker._ParkedLauncher(
        12345, release_write, exec_status_read=status_read,
        broker_report_read=report_read, broker_ack_write=ack_write,
    )
    try:
        os.close(status_write)
        status_write = -1

        def callback(*, deadline, clock):
            assert runner_ipc.read_frame(
                release_read, max_frame_bytes=protocol.MAX_FRAME_BYTES,
            ) == protocol.encode_request(request)
            runner_ipc.require_eof(release_read)
            events.append("post_eof_callback")

        launcher._release_callback = callback
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(runner_worker.os, "kill", lambda *_args: events.append("sigcont"))
        try:
            assert launcher.release_for_exec(
                request, deadline=time.monotonic() + 1,
            ) is True
        finally:
            monkeypatch.undo()
        assert events == ["sigcont", "post_eof_callback"]
        assert launcher._broker_report_read == launcher._broker_ack_write == -1
    finally:
        for fd in (release_read, status_read, status_write, report_read,
                   report_write, ack_read, ack_write):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def test_no_policy_release_closes_private_parent_bootstrap_fds(monkeypatch):
    release_read, release_write = os.pipe()
    status_read, status_write = os.pipe()
    report_read, report_write = os.pipe()
    ack_read, ack_write = os.pipe()
    launcher = runner_worker._ParkedLauncher(
        12345, release_write, exec_status_read=status_read,
        broker_report_read=report_read, broker_ack_write=ack_write,
    )
    try:
        os.close(status_write)
        status_write = -1
        monkeypatch.setattr(runner_worker.os, "kill", lambda *_args: None)
        assert launcher.release_for_exec(
            _request(), deadline=time.monotonic() + 1,
        ) is True
        assert launcher._release_callback is None
        assert launcher._broker_report_read == launcher._broker_ack_write == -1
        assert _closed(report_read) and _closed(ack_write)
    finally:
        for fd in (release_read, status_read, status_write, report_read,
                   report_write, ack_read, ack_write):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def test_malformed_policy_refuses_before_ack_and_closes_handoff_fds(monkeypatch):
    report_read, report_write = os.pipe()
    ack_read, ack_write = os.pipe()
    listener_read, listener_write = os.pipe()
    pidfd_read, pidfd_write = os.pipe()
    request = _request(environment=((PRIVATE_POLICY_ENV, "not-json"),))
    launcher = SimpleNamespace(
        pid=12345,
        _broker_report_read=report_read,
        _broker_ack_write=ack_write,
        _release_callback=None,
        _network_broker_session=None,
    )
    handoff = ListenerHandoff(12345, pidfd_read, 9, listener_read, "standard")
    acknowledged = []
    monkeypatch.setattr(runner_worker, "acquire_worker_subreaper", lambda: None)
    monkeypatch.setattr(runner_worker, "seal_worker_identity", lambda: None)
    monkeypatch.setattr(
        runner_worker, "duplicate_reported_listener",
        lambda *_args, **_kwargs: handoff,
    )
    monkeypatch.setattr(runner_worker, "verify_listener_bootstrap", lambda *_a, **_k: None)
    monkeypatch.setattr(
        runner_worker, "acknowledge_listener",
        lambda *_args, **_kwargs: acknowledged.append(True),
    )
    try:
        runner_worker._configure_network_broker(request, launcher)
        with pytest.raises(NetworkBrokerRefused, match="network_broker_policy_invalid"):
            launcher._release_callback(
                deadline=time.monotonic() + 1, clock=time.monotonic,
            )
        assert acknowledged == []
        assert launcher._broker_report_read == -1
        assert _closed(report_read)
        assert _closed(listener_read) and _closed(pidfd_read)
    finally:
        for fd in (report_read, report_write, ack_read, ack_write,
                   listener_read, listener_write, pidfd_read, pidfd_write):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def test_policy_handoff_verifies_parses_and_starts_before_ack(monkeypatch):
    report_read, report_write = os.pipe()
    ack_read, ack_write = os.pipe()
    events = []
    request = _request(environment=((PRIVATE_POLICY_ENV, "policy-wire"),))
    launcher = SimpleNamespace(
        pid=12345,
        _broker_report_read=report_read,
        _broker_ack_write=ack_write,
        _release_callback=None,
        _network_broker_session=None,
    )
    handoff = SimpleNamespace(child_pidfd=444, profile="standard")
    monkeypatch.setattr(
        runner_worker, "acquire_worker_subreaper",
        lambda: events.append("subreaper"),
    )
    monkeypatch.setattr(
        runner_worker, "seal_worker_identity",
        lambda: events.append("seal"),
    )

    class FakePolicy:
        request_id = request.request_id
        tool = request.tool

        @classmethod
        def from_json(cls, raw):
            assert raw == "policy-wire"
            events.append("parse")
            return cls()

    class FakeSession:
        def __init__(self, observed_handoff, policy, **kwargs):
            assert observed_handoff is handoff and isinstance(policy, FakePolicy)
            assert kwargs["expected_profile"] == "standard"
            events.append("session_init")

        def start(self):
            events.append("session_start")

        def stop(self):
            events.append("session_stop")

    def duplicate(*_args, **kwargs):
        assert kwargs["abort_child_on_failure"] is False
        events.append("duplicate")
        return handoff

    def verify(*_args, **kwargs):
        assert kwargs["abort_child_on_failure"] is False
        events.append("verify")

    monkeypatch.setattr(runner_worker, "duplicate_reported_listener", duplicate)
    monkeypatch.setattr(runner_worker, "verify_listener_bootstrap", verify)
    monkeypatch.setattr(runner_worker, "BrokerPolicy", FakePolicy)
    monkeypatch.setattr(runner_worker, "NetworkBrokerSession", FakeSession)
    monkeypatch.setattr(
        runner_worker, "acknowledge_listener",
        lambda *_args, **_kwargs: events.append("ack"),
    )
    try:
        runner_worker._configure_network_broker(request, launcher)
        launcher._release_callback(
            deadline=time.monotonic() + 1, clock=time.monotonic,
        )
        assert events == [
            "subreaper", "seal", "duplicate", "verify", "parse",
            "session_init", "session_start", "ack",
        ]
        assert launcher._broker_report_read == launcher._broker_ack_write == -1
        assert isinstance(launcher._network_broker_session, FakeSession)
    finally:
        for fd in (report_read, report_write, ack_read, ack_write):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def test_incomplete_broker_summary_cannot_settle_as_tool_success(monkeypatch):
    events = []

    class IncompleteSession:
        def settle_after_tasks(self, *, deadline_monotonic):
            assert deadline_monotonic > time.monotonic()
            events.append("settle")

        def summary(self):
            events.append("summary")
            return {"complete": False, "fatal": "fixture"}

        def stop(self):
            events.append("stop")

    launcher = SimpleNamespace(_network_broker_session=IncompleteSession())
    with pytest.raises(
        NetworkBrokerRefused, match="network_broker_settlement_incomplete",
    ):
        runner_worker._settle_network_broker(launcher)
    assert launcher._network_broker_session is None
    assert events == ["settle", "summary", "stop"]


def test_complete_broker_summary_is_returned_once():
    expected = {"complete": True, "records": []}

    class CompleteSession:
        def settle_after_tasks(self, *, deadline_monotonic):
            assert deadline_monotonic > time.monotonic()

        def summary(self):
            return expected

        def stop(self):
            raise AssertionError("complete session must not be stopped twice")

    launcher = SimpleNamespace(_network_broker_session=CompleteSession())
    assert runner_worker._settle_network_broker(launcher) is expected
    assert launcher._network_broker_session is None
    assert runner_worker._settle_network_broker(launcher) is None
