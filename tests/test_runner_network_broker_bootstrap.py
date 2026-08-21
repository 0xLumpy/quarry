"""Focused runner-owned seccomp listener bootstrap seams."""
from __future__ import annotations

import os
import json
import time
from types import SimpleNamespace

import pytest

from quarry_recon import runner_ipc, runner_protocol as protocol, runner_worker
from quarry_recon.network_broker import BrokerPolicy, ListenerHandoff, NetworkBrokerRefused
from quarry_recon.network_policy import PRIVATE_POLICY_ENV


pytestmark = pytest.mark.offline


@pytest.fixture(autouse=True)
def _do_not_seal_the_pytest_process(monkeypatch):
    """Unit bootstrap calls must not irreversibly make the pytest parent non-dumpable."""
    monkeypatch.setattr(runner_worker, "seal_worker_identity", lambda: None)


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


def test_browser_stdio_isolated_from_controller_stream_writers(monkeypatch):
    events = []
    monkeypatch.setattr(
        runner_worker.os, "open",
        lambda path, flags: events.append(("open", path, flags)) or 19,
    )
    monkeypatch.setattr(
        runner_worker.os, "dup2",
        lambda source, target, **kwargs: events.append(
            ("dup2", source, target, kwargs.get("inheritable")),
        ),
    )
    monkeypatch.setattr(
        runner_worker, "_close_quietly",
        lambda fd: events.append(("close", fd)),
    )
    runner_worker._isolate_browser_stdio()
    assert events[0][0:2] == ("open", "/dev/null")
    assert events[1:] == [
        ("dup2", 19, 0, True), ("dup2", 19, 1, True),
        ("dup2", 19, 2, True), ("close", 19),
    ]


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
            runner_worker._configure_network_broker(
                request, launcher, settlement_deadline=time.monotonic() + 5,
            )
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


def test_private_browser_launch_environment_is_refused_without_policy():
    request = _request(environment=((
        runner_worker._PRIVATE_BROWSER_LAUNCH_ENV, '{"forged":true}',
    ),))
    with pytest.raises(
        RuntimeError, match="network_browser_launch_environment_forbidden",
    ):
        runner_worker._configure_network_broker(
            request, SimpleNamespace(),
            settlement_deadline=time.monotonic() + 1,
        )


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
        runner_worker._configure_network_broker(
            request, launcher, settlement_deadline=time.monotonic() + 5,
        )
        assert events == ["parse", "subreaper", "seal"]
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
        ("params.nuclei_scan", "nuclei",
         ("nuclei", "-duc", "-l", "targets", "-pt", "http,dns"),
         "nuclei-authorized-http", "http,dns", "-p", "socks5", ("-pi",)),
        ("params.nuclei_scan", "nuclei",
         ("nuclei", "-duc", "-l", "targets", "-pt", "tcp"),
         "nuclei-authorized-http", "tcp", "-p", "socks5", ("-pi",)),
        ("params.oob_control", "interactsh-client",
         ("interactsh-client", "-duc", "-json"),
         "oob-control-proxy", "none", "", "http", ()),
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
    settlement_deadline = time.monotonic() + 5

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
            assert kwargs["deadline_monotonic"] == settlement_deadline
            self.endpoint = ("127.0.0.1", 43123)
            events.append("proxy_init")

        def start(self):
            events.append("proxy_start")

    class FakeSession:
        def __init__(self, observed_handoff, policy, **kwargs):
            assert observed_handoff is handoff and isinstance(policy, FakePolicy)
            assert kwargs["control_registry"] is launcher._network_proxy.registry
            assert kwargs["effect_fence"] is launcher._network_proxy.fence
            assert kwargs["deadline_monotonic"] == settlement_deadline
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
        child_request = runner_worker._configure_network_broker(
            request, launcher, settlement_deadline=settlement_deadline,
        )
        assert events == ["parse", "proxy_init", "proxy_start"]
        assert request.argv == cmd
        assert protocol.request_digest(request) == original_digest
        if proxy_flag:
            assert child_request.argv == request.argv + (
                proxy_flag, f"{scheme}://127.0.0.1:43123", *extra,
            )
            assert child_request.environment == request.environment
        else:
            assert child_request.argv == request.argv
            environment = dict(child_request.environment)
            assert environment["HTTP_PROXY"] == "http://127.0.0.1:43123"
            assert environment["HTTPS_PROXY"] == "http://127.0.0.1:43123"
            assert environment[PRIVATE_POLICY_ENV] == "policy-wire"

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


def test_oob_caller_proxy_environment_is_refused_before_proxy_start(monkeypatch):
    request = _request(
        environment=(
            (PRIVATE_POLICY_ENV, "policy-wire"),
            ("HTTPS_PROXY", "http://caller.invalid"),
        ),
        tool="interactsh-client",
        cmd=("interactsh-client", "-duc", "-json"),
    )
    launcher = SimpleNamespace(
        pid=12345,
        _broker_report_read=-1,
        _broker_ack_write=-1,
        _release_callback=None,
        _network_broker_session=None,
        _network_proxy=None,
    )

    class FakePolicy:
        request_id = request.request_id
        tool = request.tool
        source_id = "params.oob_control"
        transport_profile = "oob-control-proxy"
        nuclei_protocol_lane = "none"

        @classmethod
        def from_json(cls, raw):
            assert raw == "policy-wire"
            return cls()

    monkeypatch.setattr(runner_worker, "BrokerPolicy", FakePolicy)
    monkeypatch.setattr(
        runner_worker, "PinnedBrowserProxy",
        lambda *_args, **_kwargs: pytest.fail("caller proxy reached proxy startup"),
    )
    with pytest.raises(RuntimeError, match="network_proxy_caller_environment_forbidden"):
        runner_worker._configure_network_broker(
            request, launcher, settlement_deadline=time.monotonic() + 5,
        )


@pytest.mark.parametrize("source_id", ("probe.gowitness", "enrich.gowitness"))
def test_gowitness_runner_injects_only_pinned_cdp_and_private_browser_launch(
        monkeypatch, tmp_path, source_id):
    browser_output, chrome_output = os.pipe()
    chrome_input, browser_input = os.pipe()
    request = _request(
        environment=((PRIVATE_POLICY_ENV, "policy-wire"), ("HOME", str(tmp_path)),
                     ("CONTROLLER_ONLY", "secret")),
        tool="gowitness",
        cmd=("gowitness", "scan", "file", "--chrome-path", "/usr/bin/true"),
    )
    identity = ("a" * 64, 123)
    settlement_deadline = time.monotonic() + 5
    policy = BrokerPolicy(
        request_id=request.request_id, source_id=source_id, tool="gowitness",
        block_private_targets=False, control_plane_cidrs=(), initial_own_ips=(),
        resolver_ips=("1.1.1.1",), control_helpers=(identity,),
        control_clients=(identity,), transport_profile="browser-pipe-proxy",
        peer_mode="target", resolver_mode="none",
    )
    launcher = SimpleNamespace(
        pid=12345, _browser_bridge_output_read=browser_output,
        _browser_bridge_input_write=browser_input, _network_proxy=None,
        _network_cdp_bridge=None,
    )

    class FakeProxy:
        endpoint = ("127.0.0.1", 43123)

        def __init__(self, observed, registry, **kwargs):
            assert observed.private_unix_roots
            self.registry = registry
            self.fence = kwargs["effect_fence"]
            assert kwargs["deadline_monotonic"] == settlement_deadline

        def start(self):
            pass

    class FakeBridge:
        endpoint = ("127.0.0.1", 43124)
        websocket_url = "ws://127.0.0.1:43124/devtools/browser/pinned"

        def __init__(self, observed, registry, **kwargs):
            assert observed.private_unix_roots
            assert kwargs["controller_identity"] == identity
            assert kwargs["expected_controller_tgid"] == launcher.pid
            assert kwargs["deadline_monotonic"] == settlement_deadline

        def start(self):
            pass

    monkeypatch.setattr(runner_worker.BrokerPolicy, "from_json", lambda _raw: policy)
    monkeypatch.setattr(runner_worker, "PinnedBrowserProxy", FakeProxy)
    monkeypatch.setattr(runner_worker, "PinnedCDPBridge", FakeBridge)
    try:
        child = runner_worker._configure_network_broker(
            request, launcher, settlement_deadline=settlement_deadline,
        )
        assert child.argv == (
            "gowitness", "scan", "file", "--chrome-wss-url",
            FakeBridge.websocket_url,
        )
        document = json.loads(dict(child.environment)[runner_worker._PRIVATE_BROWSER_LAUNCH_ENV])
        assert document["argv"][0] == "/usr/bin/true"
        assert "--remote-debugging-pipe" in document["argv"]
        assert any(value == "--proxy-server=http://127.0.0.1:43123"
                   for value in document["argv"])
        assert all("wss" not in value for value in document["argv"])
        assert document["environment"]["PATH"] == "/usr/bin:/bin"
        assert document["environment"]["LANG"] == "C.UTF-8"
        assert PRIVATE_POLICY_ENV not in document["environment"]
        assert runner_worker.PRIVATE_REDACTIONS_ENV not in document["environment"]
        assert "CONTROLLER_ONLY" not in document["environment"]
        profile = next(
            value.partition("=")[2] for value in document["argv"]
            if value.startswith("--user-data-dir=")
        )
        browser_root = os.path.dirname(profile)
        assert os.path.dirname(browser_root) == str(tmp_path)
        assert os.path.basename(browser_root).startswith("c-")
        assert len(os.path.basename(browser_root).encode()) == 10
        assert document["environment"]["TMPDIR"] == os.path.join(
            browser_root, "tmp",
        )
    finally:
        for fd in (browser_output, chrome_output, chrome_input, browser_input):
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
        runner_worker._configure_network_broker(
            request, launcher, settlement_deadline=time.monotonic() + 5,
        )


@pytest.mark.parametrize(
    "cmd",
    (
        ("gowitness", "scan", "file", "--chrome-wss-url", "ws://caller.invalid"),
        ("gowitness", "scan", "file", "--chrome-wss-url=ws://caller.invalid"),
    ),
)
def test_gowitness_caller_cdp_is_refused_before_proxy_start(monkeypatch, cmd):
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
        lambda *_args, **_kwargs: pytest.fail("caller CDP reached proxy startup"),
    )
    with pytest.raises(RuntimeError, match="network_cdp_caller_argument_forbidden"):
        runner_worker._configure_network_broker(
            request, launcher, settlement_deadline=time.monotonic() + 5,
        )


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
        runner_worker._configure_network_broker(
            request, launcher, settlement_deadline=time.monotonic() + 5,
        )


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


def test_gowitness_settlement_orders_controller_cdp_browser_and_reap(monkeypatch):
    events = []

    class Session:
        def __init__(self, name):
            self.name = name

        def settle_after_tasks(self, **_kwargs):
            events.append(self.name + "_settle")

        def summary(self):
            return {"complete": True, "profile": self.name}

        def stop(self):
            events.append(self.name + "_stop")

    class Bridge:
        def summary(self):
            return {
                "complete": "bridge_stop" in events,
                "settled_connections": 1, "active_client": False,
            }

        def stop(self):
            events.append("bridge_stop")

    class Proxy:
        def stop(self):
            events.append("proxy_stop")

        def summary(self):
            return {"complete": True}

    class Fence:
        def cancel(self):
            events.append("cancel")

    launcher = SimpleNamespace(
        _network_broker_session=Session("controller"),
        _network_browser_broker_session=Session("browser"),
        _network_cdp_bridge=Bridge(), _network_proxy=Proxy(),
        _network_effect_fence=Fence(), _browser_pid=43210,
        _browser_pidfd=99,
    )
    monkeypatch.setattr(
        runner_worker.signal, "pidfd_send_signal",
        lambda _fd, sig: events.append("pidfd_probe" if sig == 0 else "pidfd_kill"),
        raising=False,
    )
    monkeypatch.setattr(
        runner_worker.os, "killpg",
        lambda pid, sig: events.append(f"browser_killpg:{pid}:{sig}"),
    )
    monkeypatch.setattr(runner_worker.os, "close", lambda fd: events.append(f"close:{fd}"))
    monkeypatch.setattr(
        runner_worker, "reap_adopted_descendants",
        lambda **_kwargs: events.append("reap") or ((43210, 9),),
    )
    monkeypatch.setattr(
        runner_worker, "_kill_adopted_browser_descendants",
        lambda *_args: events.append("kill_adopted"),
    )
    summary = runner_worker._settle_network_broker(launcher)
    assert summary["adopted_descendants"] == 1
    assert events == [
        "controller_settle", "pidfd_probe",
        f"browser_killpg:43210:{runner_worker.signal.SIGKILL}", "close:99",
        "kill_adopted", "browser_settle", "bridge_stop", "proxy_stop", "reap",
    ]
    assert launcher._network_broker_session is None
    assert launcher._network_browser_broker_session is None


def test_gowitness_incomplete_controller_cancels_every_shared_component(monkeypatch):
    events = []

    class IncompleteController:
        def settle_after_tasks(self, **_kwargs):
            events.append("controller_settle")

        def summary(self):
            return {"complete": False}

        def stop(self):
            events.append("controller_stop")

    class Component:
        def __init__(self, name):
            self.name = name

        def stop(self):
            events.append(self.name + "_stop")

    class Fence:
        def cancel(self):
            events.append("cancel")

    launcher = SimpleNamespace(
        _network_broker_session=IncompleteController(),
        _network_browser_broker_session=Component("browser"),
        _network_cdp_bridge=Component("bridge"),
        _network_proxy=Component("proxy"), _network_effect_fence=Fence(),
        _browser_pid=None, _browser_pidfd=-1,
    )
    monkeypatch.setattr(
        runner_worker, "_kill_adopted_browser_descendants", lambda *_args: None,
    )
    monkeypatch.setattr(
        runner_worker, "reap_adopted_descendants", lambda **_kwargs: (),
    )
    monkeypatch.setattr(
        runner_worker, "_kill_and_reap_adopted_children", lambda _deadline: (),
    )
    with pytest.raises(NetworkBrokerRefused, match="settlement_incomplete"):
        runner_worker._settle_network_broker(launcher)
    assert events == [
        "controller_settle", "cancel", "controller_stop", "browser_stop",
        "bridge_stop", "proxy_stop",
    ]


def test_gowitness_fatal_cdp_fails_without_spending_settlement_deadline(monkeypatch):
    events = []

    class Controller:
        def settle_after_tasks(self, **_kwargs):
            events.append("controller_settle")

        def summary(self):
            return {"complete": True}

        def stop(self):
            events.append("controller_stop")

    class Component:
        def __init__(self, name):
            self.name = name

        def stop(self):
            events.append(self.name + "_stop")

    class Bridge(Component):
        def summary(self):
            return {
                "fatal": "network_cdp_chrome_pipe_closed",
                "thread_alive": False,
                "settled_connections": 0,
                "active_client": False,
            }

    class Fence:
        def cancel(self):
            events.append("cancel")

    launcher = SimpleNamespace(
        _network_broker_session=Controller(),
        _network_browser_broker_session=Component("browser"),
        _network_cdp_bridge=Bridge("bridge"),
        _network_proxy=Component("proxy"), _network_effect_fence=Fence(),
        _browser_pid=None, _browser_pidfd=-1,
    )
    monkeypatch.setattr(
        runner_worker, "_kill_and_reap_adopted_children",
        lambda _deadline: events.append("adopted_sweep") or (),
    )
    monkeypatch.setattr(
        runner_worker.time, "sleep",
        lambda _seconds: pytest.fail("fatal bridge settlement slept"),
    )
    with pytest.raises(NetworkBrokerRefused, match="cdp_settlement_incomplete"):
        runner_worker._settle_network_broker(
            launcher, deadline_monotonic=time.monotonic() + 30,
        )
    assert events == [
        "controller_settle", "cancel", "adopted_sweep", "controller_stop",
        "browser_stop", "bridge_stop", "proxy_stop",
    ]


def test_gowitness_partial_start_still_closes_started_components(monkeypatch):
    events = []

    class Component:
        def __init__(self, name):
            self.name = name

        def stop(self):
            events.append(self.name + "_stop")

    class Fence:
        def cancel(self):
            events.append("cancel")

    launcher = SimpleNamespace(
        _network_broker_session=None, _network_browser_broker_session=None,
        _network_cdp_bridge=Component("bridge"),
        _network_proxy=Component("proxy"), _network_effect_fence=Fence(),
        _browser_pid=43210, _browser_pidfd=-1, _browser_ack_write=-1,
        _browser_preexec_identity_verified=True,
    )
    monkeypatch.setattr(
        runner_worker.os, "killpg",
        lambda pid, sig: events.append(f"browser_killpg:{pid}:{sig}"),
    )
    monkeypatch.setattr(
        runner_worker, "_kill_and_reap_adopted_children",
        lambda _deadline: events.append("adopted_sweep") or ((43211, 9),),
    )
    with pytest.raises(NetworkBrokerRefused, match="authority_invalid"):
        runner_worker._settle_network_broker(
            launcher, deadline_monotonic=time.monotonic() + 1,
        )
    assert events == [
        "cancel",
        f"browser_killpg:43210:{runner_worker.signal.SIGKILL}",
        "adopted_sweep", "bridge_stop", "proxy_stop",
    ]


def test_browser_pid_without_durable_preexec_proof_refuses_pgid_fallback(
        monkeypatch):
    events = []
    launcher = SimpleNamespace(
        _browser_pid=43210, _browser_pidfd=-1,
        _browser_ack_write=-1, _browser_preexec_identity_verified=False,
    )
    monkeypatch.setattr(
        runner_worker.os, "killpg",
        lambda *_args: events.append("unexpected_kill"),
    )
    with pytest.raises(NetworkBrokerRefused, match="identity_invalid"):
        runner_worker._kill_browser_authority(
            launcher, {"browser_killed": False},
        )
    assert events == []


def test_failed_partial_start_pidfd_kills_each_adopted_direct_child(monkeypatch):
    events = []
    snapshots = iter(("43211 43212", ""))

    class Snapshot:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _size):
            return next(snapshots)

    monkeypatch.setattr("builtins.open", lambda *_args, **_kwargs: Snapshot())
    monkeypatch.setattr(
        runner_worker.os, "pidfd_open",
        lambda pid, flags: events.append(("open", pid, flags)) or pid + 100,
        raising=False,
    )
    monkeypatch.setattr(
        runner_worker.signal, "pidfd_send_signal",
        lambda fd, sig: events.append(("kill", fd, sig)),
        raising=False,
    )
    monkeypatch.setattr(
        runner_worker.os, "close", lambda fd: events.append(("close", fd)),
    )
    waits = iter(((43211, 9), (43212, 9)))

    def waitpid(_pid, _flags):
        try:
            return next(waits)
        except StopIteration:
            raise ChildProcessError

    monkeypatch.setattr(runner_worker.os, "waitpid", waitpid)
    assert runner_worker._kill_and_reap_adopted_children(
        time.monotonic() - 1,
    ) == ((43211, 9), (43212, 9))
    assert events == [
        ("open", 43211, 0),
        ("kill", 43311, runner_worker.signal.SIGKILL),
        ("close", 43311),
        ("open", 43212, 0),
        ("kill", 43312, runner_worker.signal.SIGKILL),
        ("close", 43312),
    ]


def test_browser_pidfd_is_tombstoned_before_ambiguous_close(monkeypatch):
    events = []
    state = {"browser_killed": False}
    launcher = SimpleNamespace(_browser_pid=43210, _browser_pidfd=99)
    monkeypatch.setattr(
        runner_worker.signal, "pidfd_send_signal", lambda *_args: None,
        raising=False,
    )
    monkeypatch.setattr(runner_worker.os, "killpg", lambda *_args: None)

    def interrupt_close(fd):
        events.append((fd, launcher._browser_pidfd))
        raise KeyboardInterrupt("close cancellation")

    monkeypatch.setattr(runner_worker.os, "close", interrupt_close)
    with pytest.raises(KeyboardInterrupt, match="close cancellation"):
        runner_worker._kill_browser_authority(launcher, state)
    assert events == [(99, -1)]
    assert state["browser_killed"]
    # Retry cannot target the stale numeric descriptor.
    runner_worker._kill_browser_authority(launcher, state)
    assert events == [(99, -1)]


def test_gowitness_cleanup_baseexception_retries_from_monotone_state(monkeypatch):
    events = []

    class Bridge:
        attempts = 0

        def stop(self):
            self.attempts += 1
            events.append(f"bridge_stop:{self.attempts}")
            if self.attempts == 1:
                raise KeyboardInterrupt("cleanup cancellation")

    class Proxy:
        def stop(self):
            events.append("proxy_stop")

    class Fence:
        def cancel(self):
            events.append("cancel")

    launcher = SimpleNamespace(
        _network_broker_session=None, _network_browser_broker_session=None,
        _network_cdp_bridge=Bridge(), _network_proxy=Proxy(),
        _network_effect_fence=Fence(), _browser_pid=None, _browser_pidfd=-1,
    )
    monkeypatch.setattr(
        runner_worker, "reap_adopted_descendants", lambda **_kwargs: (),
    )
    monkeypatch.setattr(
        runner_worker, "_kill_and_reap_adopted_children", lambda _deadline: (),
    )
    deadline = time.monotonic() + 1
    with pytest.raises(KeyboardInterrupt, match="cleanup cancellation"):
        runner_worker._settle_network_broker(
            launcher, deadline_monotonic=deadline,
        )
    state = launcher._network_gowitness_state
    assert state["cleanup_required"] and not state["cleanup_complete"]
    assert state["fence_cancelled"] and state["browser_killed"]
    assert runner_worker._settle_network_broker(
        launcher, deadline_monotonic=deadline,
    ) == {"complete": False, "cleanup_complete": True}
    assert events == ["cancel", "bridge_stop:1", "bridge_stop:2", "proxy_stop"]
    assert state["cleanup_complete"]
