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


def _request(*, environment=(), tool="fixture", cmd=("/bin/true",)):
    return protocol.normalize_invocation(
        request_id="ab" * 16,
        tool=tool,
        cmd=cmd,
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


def test_malformed_policy_refuses_before_launcher_release(monkeypatch):
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
        with pytest.raises(NetworkBrokerRefused, match="network_broker_policy_invalid"):
            runner_worker._configure_network_broker(request, launcher)
        assert acknowledged == []
        assert launcher._release_callback is None
        assert not _closed(report_read)
        assert not _closed(listener_read) and not _closed(pidfd_read)
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
        source_id = "fixture"
        transport_profile = "test-exact-approved"

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
        assert events == ["parse"]
        launcher._release_callback(
            deadline=time.monotonic() + 1, clock=time.monotonic,
        )
        assert events == [
            "parse", "subreaper", "seal", "duplicate", "verify",
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


@pytest.mark.parametrize(
    ("source_id", "tool", "cmd", "profile", "lane", "proxy_flag", "scheme", "extra"),
    (
        ("crawl.katana_standard", "katana", ("katana", "-duc", "-silent"),
         "target-http-proxy", "none", "-proxy", "http", ()),
        ("probe.gowitness", "gowitness", ("gowitness", "scan", "file"),
         "browser-pipe-proxy", "none", "--chrome-proxy", "http", ()),
        ("enrich.gowitness", "gowitness", ("gowitness", "scan", "file"),
         "browser-pipe-proxy", "none", "--chrome-proxy", "http", ()),
        ("params.nuclei_scan", "nuclei",
         ("nuclei", "-duc", "-l", "targets", "-pt", "http,dns"),
         "nuclei-authorized-http", "http,dns", "-p", "socks5", ("-pi",)),
        ("params.nuclei_scan", "nuclei",
         ("nuclei", "-duc", "-l", "targets", "-pt", "tcp"),
         "nuclei-authorized-http", "tcp", "-p", "socks5", ("-pi",)),
    ),
)
def test_proxy_is_runner_injected_before_release_and_shares_authority(
        monkeypatch, source_id, tool, cmd, profile, lane, proxy_flag, scheme, extra):
    report_read, report_write = os.pipe()
    ack_read, ack_write = os.pipe()
    events = []
    request = _request(
        environment=((PRIVATE_POLICY_ENV, "policy-wire"),),
        tool=tool, cmd=cmd,
    )
    launcher = SimpleNamespace(
        pid=12345,
        _broker_report_read=report_read,
        _broker_ack_write=ack_write,
        _release_callback=None,
        _network_broker_session=None,
        _network_proxy=None,
    )
    handoff = SimpleNamespace(child_pidfd=444, profile="standard")
    expected_source_id = source_id
    expected_profile = profile

    class FakePolicy:
        request_id = request.request_id
        tool = request.tool
        source_id = expected_source_id
        transport_profile = expected_profile
        nuclei_protocol_lane = lane

        @classmethod
        def from_json(cls, raw):
            assert raw == "policy-wire"
            events.append("parse")
            return cls()

    class FakeProxy:
        def __init__(self, policy, registry, **kwargs):
            assert isinstance(policy, FakePolicy)
            self.registry = registry
            self.fence = kwargs["effect_fence"]
            self.endpoint = ("127.0.0.1", 43123)
            events.append("proxy_init")

        def start(self):
            events.append("proxy_start")

    class FakeSession:
        def __init__(self, observed_handoff, policy, **kwargs):
            assert observed_handoff is handoff and isinstance(policy, FakePolicy)
            assert kwargs["control_registry"] is launcher._network_proxy.registry
            assert kwargs["effect_fence"] is launcher._network_proxy.fence
            events.append("session_init")

        def start(self):
            events.append("session_start")

        def stop(self):
            events.append("session_stop")

    monkeypatch.setattr(runner_worker, "BrokerPolicy", FakePolicy)
    monkeypatch.setattr(runner_worker, "PinnedBrowserProxy", FakeProxy)
    monkeypatch.setattr(runner_worker, "NetworkBrokerSession", FakeSession)
    monkeypatch.setattr(runner_worker, "acquire_worker_subreaper", lambda: None)
    monkeypatch.setattr(runner_worker, "seal_worker_identity", lambda: None)
    monkeypatch.setattr(
        runner_worker, "duplicate_reported_listener", lambda *_a, **_k: handoff,
    )
    monkeypatch.setattr(
        runner_worker, "verify_listener_bootstrap", lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        runner_worker, "acknowledge_listener", lambda *_a, **_k: events.append("ack"),
    )
    try:
        original_digest = protocol.request_digest(request)
        child_request = runner_worker._configure_network_broker(request, launcher)
        assert events == ["parse", "proxy_init", "proxy_start"]
        assert request.argv == cmd
        assert protocol.request_digest(request) == original_digest
        assert child_request.argv == request.argv + (
            proxy_flag, f"{scheme}://127.0.0.1:43123", *extra,
        )

        launcher._release_callback(
            deadline=time.monotonic() + 1, clock=time.monotonic,
        )
        assert events[-3:] == ["session_init", "session_start", "ack"]
    finally:
        for fd in (report_read, report_write, ack_read, ack_write):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


@pytest.mark.parametrize(
    "cmd",
    (
        ("gowitness", "scan", "file", "--chrome-proxy", "http://caller.invalid"),
        ("gowitness", "scan", "file", "--proxy=http://caller.invalid"),
    ),
)
def test_gowitness_caller_proxy_is_refused_before_proxy_start(monkeypatch, cmd):
    request = _request(
        environment=((PRIVATE_POLICY_ENV, "policy-wire"),), tool="gowitness", cmd=cmd,
    )
    launcher = SimpleNamespace(
        _network_control_registry=None, _network_effect_fence=None,
    )

    class FakePolicy:
        request_id = request.request_id
        tool = request.tool
        source_id = "probe.gowitness"
        transport_profile = "browser-pipe-proxy"

        @classmethod
        def from_json(cls, raw):
            assert raw == "policy-wire"
            return cls()

    monkeypatch.setattr(runner_worker, "BrokerPolicy", FakePolicy)
    monkeypatch.setattr(
        runner_worker, "PinnedBrowserProxy",
        lambda *_args, **_kwargs: pytest.fail("caller proxy reached proxy startup"),
    )
    with pytest.raises(RuntimeError, match="network_proxy_caller_argument_forbidden"):
        runner_worker._configure_network_broker(request, launcher)


@pytest.mark.parametrize(
    "flag",
    ("-p", "-proxy", "-pi", "-proxy-internal"),
)
def test_nuclei_caller_proxy_is_refused_before_proxy_start(monkeypatch, flag):
    request = _request(
        environment=((PRIVATE_POLICY_ENV, "policy-wire"),),
        tool="nuclei", cmd=("nuclei", "-duc", flag),
    )
    launcher = SimpleNamespace(
        _network_control_registry=None, _network_effect_fence=None,
    )

    class FakePolicy:
        request_id = request.request_id
        tool = request.tool
        source_id = "params.nuclei_scan"
        transport_profile = "nuclei-authorized-http"
        nuclei_protocol_lane = "http,dns"

        @classmethod
        def from_json(cls, raw):
            assert raw == "policy-wire"
            return cls()

    monkeypatch.setattr(runner_worker, "BrokerPolicy", FakePolicy)
    monkeypatch.setattr(
        runner_worker, "PinnedBrowserProxy",
        lambda *_args, **_kwargs: pytest.fail("caller proxy reached proxy startup"),
    )
    with pytest.raises(RuntimeError, match="network_proxy_caller_argument_forbidden"):
        runner_worker._configure_network_broker(request, launcher)


def test_incomplete_proxy_cancels_shared_fence_and_stops_broker(monkeypatch):
    events = []

    class IncompleteProxy:
        def stop(self):
            events.append("proxy_stop")

        def summary(self):
            return {"complete": False}

    class Broker:
        def settle_after_tasks(self, **_kwargs):
            events.append("broker_settle")

        def summary(self):
            return {"complete": True}

        def stop(self):
            events.append("broker_stop")

    fence = runner_worker.NetworkEffectFence()
    launcher = SimpleNamespace(
        _network_proxy=IncompleteProxy(),
        _network_broker_session=Broker(),
        _network_effect_fence=fence,
    )
    with pytest.raises(
        NetworkBrokerRefused, match="network_proxy_settlement_incomplete",
    ):
        runner_worker._settle_network_broker(launcher)
    assert fence.is_set()
    assert events == ["proxy_stop", "broker_settle", "broker_stop"]


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
