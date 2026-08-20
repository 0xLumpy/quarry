"""Focused target-DNS wire authority and resolver-pinning seams."""
from __future__ import annotations

import json
import os
import socket
import struct
import time
from types import SimpleNamespace

import pytest

from quarry_recon import (
    network_dns,
    network_policy,
    runner_protocol as protocol,
    runner_worker,
)
from quarry_recon.network_broker import (
    BrokerPolicy,
    NetworkBrokerRefused,
    NetworkEffectFence,
)


pytestmark = pytest.mark.offline


def _policy(source="dns.dnsx_records", *, cidrs=(), **kwargs):
    return BrokerPolicy(
        "a" * 32, source, "dnsx", False, (), ("10.203.0.2",),
        ("1.1.1.1",), ("example.test",), (), cidrs, (),
        authority_class="target", transport_profile="target-dns",
        peer_mode="deny-all", resolver_mode="mediated-public",
        **kwargs,
    )


def _query(name: str, qtype: int, *, flags=0x0100, trailing=b"") -> bytes:
    labels = b"".join(
        bytes((len(label),)) + label.encode("ascii") for label in name.split(".")
    )
    return b"\x00\x01" + flags.to_bytes(2, "big") + b"\x00\x01" + b"\x00\x00" * 3 \
        + labels + b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01" + trailing


def _dnsx_query(name: str, qtype: int) -> bytes:
    query = bytearray(_query(name, qtype))
    query[10:12] = b"\x00\x01"
    return bytes(query) + struct.pack("!BHHIH", 0, 41, 4096, 0, 0)


def test_target_dns_query_is_source_scoped_and_strict():
    policy = _policy()
    assert policy.decide_dns_question(_query("www.example.test", 1))[0] == "allow"
    assert policy.decide_dns_question(_query("www.outside.test", 1))[0] == "deny"
    assert policy.decide_dns_question(_query("www.example.test", 12))[0] == "deny"
    assert policy.decide_dns_question(_query("www.example.test", 1, trailing=b"x"))[0] == "deny"
    assert policy.decide_dns_question(_query("WWW.example.test", 1))[0] == "deny"


def test_target_dns_accepts_only_dnsx_empty_edns_suffix():
    policy = _policy()
    assert policy.decide_dns_question(_dnsx_query("www.example.test", 1))[0] == "allow"
    assert policy.decide_dns_question(
        _dnsx_query("www.example.test", 1)[:-2] + b"\x00\x01",
    )[0] == "deny"
    query = bytearray(_dnsx_query("www.example.test", 1))
    query[-1] = 1
    assert policy.decide_dns_question(bytes(query))[0] == "deny"


def test_target_dns_ptr_is_limited_to_effective_cidrs():
    policy = _policy("horizontal.revdns", cidrs=("10.0.0.0/24",))
    assert policy.decide_dns_question(_query("2.0.0.10.in-addr.arpa", 12))[0] == "allow"
    assert policy.decide_dns_question(_query("2.0.0.11.in-addr.arpa", 12))[0] == "deny"
    assert policy.decide_dns_question(_query("2.0.0.10.in-addr.arpa", 1))[0] == "deny"


def test_target_dns_admits_only_held_loopback_mediator(monkeypatch):
    from quarry_recon import netguard

    class Snapshot:
        protected_ips = ("10.203.0.2",)
        broadcast_ips = ()
        unicast_ips = ("10.203.0.2",)

    monkeypatch.setattr(netguard, "interface_snapshot", lambda: Snapshot())
    policy = _policy(dns_mediator_endpoint=("127.0.0.1", 53053))
    assert policy.decide("1.1.1.1", 53, socket.SOCK_DGRAM, socket.IPPROTO_UDP)[0] == "deny"
    assert policy.decide("127.0.0.1", 53053, socket.SOCK_DGRAM, socket.IPPROTO_UDP)[0] == "allow"
    assert policy.decide("127.0.0.1", 53053, socket.SOCK_STREAM, socket.IPPROTO_TCP)[0] == "allow"
    assert policy.decide_dns("1.1.1.1", 53, socket.SOCK_STREAM, socket.IPPROTO_TCP)[0] == "allow"


def test_target_dns_authentication_is_runtime_only_and_never_reaches_child_env(
        monkeypatch):
    secret = b"s" * 32
    scope = network_policy.NetworkPolicyScope(
        block_private_targets=False, apex_domains=("example.test",),
        own_ips=("10.203.0.2",), resolver_ips=("1.1.1.1",),
    )
    document = scope.broker_policy(
        request_id="b" * 32, source_id="dns.dnsx_records", tool="dnsx",
    )
    policy_wire = json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    )
    assert "dns_mediator_authentication" not in document
    assert secret.hex() not in policy_wire

    with_secret = dict(document)
    with_secret["dns_mediator_authentication"] = secret.hex()
    with pytest.raises(NetworkBrokerRefused, match="network_broker_policy_invalid"):
        BrokerPolicy.from_json(json.dumps(with_secret))

    request = protocol.normalize_invocation(
        request_id="b" * 32, tool="dnsx", cmd=("dnsx", "-silent"), timeout=3,
        env={network_policy.PRIVATE_POLICY_ENV: policy_wire}, base_environment={},
        raw_path="/tmp/dns.stdout", stderr_path="/tmp/dns.stderr",
    ).worker
    launcher = SimpleNamespace(_release_callback=None)
    monkeypatch.setattr(runner_worker.os, "urandom", lambda _size: secret)
    child_request = runner_worker._configure_network_broker(request, launcher)
    try:
        child_environment = dict(child_request.environment)
        assert child_environment[network_policy.PRIVATE_POLICY_ENV] == policy_wire
        assert all(secret.hex() not in value for value in child_environment.values())
        assert all("dns_mediator_authentication" not in key for key in child_environment)
    finally:
        launcher._network_dns_mediator.stop()
        runner_worker._cleanup_target_dns_resolvers(launcher)


def test_mediator_checks_scope_before_the_existing_upstream_exchange(monkeypatch):
    policy = _policy()
    fence = NetworkEffectFence()
    seen = []

    def exchange(_policy, _resolver, query, **_kwargs):
        seen.append(query)
        return query[:2] + b"\x81\x80" + query[4:]

    monkeypatch.setattr(network_dns, "_exchange", exchange)
    mediator = network_dns.TargetDNSMediator(
        policy, authentication=b"m" * 32, deadline_monotonic=time.monotonic() + 5,
        effect_fence=fence,
    )
    mediator.start()
    try:
        allowed = _query("www.example.test", 1)
        assert mediator._relay(allowed) == allowed[:2] + b"\x81\x80" + allowed[4:]
        rejected = _query("www.outside.test", 1)
        assert mediator._relay(rejected)[2:4] == b"\x81\x85"
        assert seen == [allowed]
        assert mediator.endpoint[0] == "127.0.0.1"
    finally:
        mediator.stop()


@pytest.mark.parametrize("response", (
    lambda query: query[:2] + b"\x81\x80" + query[4:12]
    + _query("outside.test", 1)[12:],
    lambda _query: (_ for _ in ()).throw(network_dns.NetworkDNSRefused("upstream")),
))
def test_mediator_refuses_unbound_or_unsettled_upstream_response(monkeypatch, response):
    policy = _policy()
    mediator = network_dns.TargetDNSMediator(
        policy, authentication=b"m" * 32, deadline_monotonic=time.monotonic() + 5,
        effect_fence=NetworkEffectFence(),
    )
    monkeypatch.setattr(
        network_dns, "_exchange", lambda _policy, _resolver, query, **_kwargs: response(query),
    )
    assert mediator._relay(_query("www.example.test", 1))[2:4] == b"\x81\x82"
    assert mediator.summary()["complete"] is False
    assert mediator.summary()["fatal"] == "network_dns_mediator_upstream_failed"
    mediator.stop()


def test_mediator_cleanup_retains_uncertain_listener_for_retry(monkeypatch):
    mediator = network_dns.TargetDNSMediator(
        _policy(), authentication=b"m" * 32, deadline_monotonic=time.monotonic() + 5,
        effect_fence=NetworkEffectFence(),
    )
    mediator.start()
    udp = mediator._udp
    original = mediator._fence.close_tracked_socket
    failed = False

    def close_once(handle, **kwargs):
        nonlocal failed
        if handle is udp and not failed:
            failed = True
            raise network_dns.NetworkDNSRefused("injected-close-fault")
        return original(handle, **kwargs)

    monkeypatch.setattr(mediator._fence, "close_tracked_socket", close_once)
    with pytest.raises(network_dns.NetworkDNSRefused, match="injected-close-fault"):
        mediator.stop()
    assert mediator._udp is udp
    mediator.stop()
    assert mediator._udp is None


def _request(cmd):
    return protocol.normalize_invocation(
        request_id="ab" * 16, tool=cmd[0], cmd=cmd, timeout=3, env={},
        base_environment={}, raw_path="/tmp/dns.stdout", stderr_path="/tmp/dns.stderr",
    ).worker


def test_runner_pins_local_dnsx_and_puredns_private_file(monkeypatch):
    policy = SimpleNamespace(resolver_ips=("1.1.1.1", "2606:4700:4700::1111"))
    dnsx = runner_worker._configure_target_dns_resolvers(
        _request(("dnsx", "-duc")), policy, SimpleNamespace(), ("127.0.0.1", 53053),
    )
    assert dnsx.argv[-2:] == ("-r", "127.0.0.1:53053")

    launcher = SimpleNamespace()
    monkeypatch.setattr(runner_worker, "_attested_massdns_path", lambda _request: "/private/massdns")
    puredns = runner_worker._configure_target_dns_resolvers(
        _request((
            "puredns", "resolve", "hosts.txt", "-r", "caller.txt",
            "-b", "/caller/massdns-a", "--bin", "/caller/massdns-b",
            "-b=/caller/massdns-c", "--bin=/caller/massdns-d",
            "--resolvers-trusted", "trusted.txt",
        )), policy, launcher, ("127.0.0.1", 53053),
    )
    path = launcher._network_resolver_path
    assert puredns.argv[-6:] == (
        "--bin", "/private/massdns", "--resolvers", path, "--resolvers-trusted", path,
    )
    assert open(path, encoding="ascii").read() == "127.0.0.1:53053\n"
    assert os.stat(path).st_mode & 0o077 == 0
    runner_worker._cleanup_target_dns_resolvers(launcher)
    assert not os.path.exists(path)


def test_runner_retains_resolver_cleanup_authority_until_retry(monkeypatch, tmp_path):
    directory = tmp_path / "resolvers"
    directory.mkdir(mode=0o700)
    path = directory / "resolvers.txt"
    path.write_text("127.0.0.1:53053\n", encoding="ascii")
    launcher = SimpleNamespace(
        _network_resolver_path=str(path),
        _network_resolver_directory=str(directory),
    )
    real_unlink = runner_worker.os.unlink
    failed = False

    def unlink_once(candidate):
        nonlocal failed
        if candidate == str(path) and not failed:
            failed = True
            raise OSError("injected cleanup fault")
        return real_unlink(candidate)

    monkeypatch.setattr(runner_worker.os, "unlink", unlink_once)
    with pytest.raises(RuntimeError, match="resolver_cleanup_failed"):
        runner_worker._cleanup_target_dns_resolvers(launcher)
    assert launcher._network_resolver_path == str(path)
    assert launcher._network_resolver_directory == str(directory)

    runner_worker._cleanup_target_dns_resolvers(launcher)
    assert launcher._network_resolver_path is None
    assert launcher._network_resolver_directory is None
    assert not directory.exists()


def test_runner_pins_dig_to_one_literal_and_broker_parseable_query():
    policy = SimpleNamespace(resolver_ips=("1.1.1.1", "8.8.8.8"))
    request = runner_worker._configure_target_dns_resolvers(
        _request(("dig", "+short", "TXT", "_dmarc.example.test")),
        policy, SimpleNamespace(), ("127.0.0.1", 53053),
    )
    assert request.argv == (
        "dig", "+short", "TXT", "_dmarc.example.test", "@127.0.0.1", "-p", "53053",
        "+noedns", "+noadflag", "+ignore", "-r",
    )
    with pytest.raises(RuntimeError, match="dig_argv_invalid"):
        runner_worker._configure_target_dns_resolvers(
            _request(("dig", "+short", "A", "example.test")),
            policy, SimpleNamespace(), ("127.0.0.1", 53053),
        )


@pytest.mark.parametrize("flag", ("-r", "--resolvers=caller.txt", "-system-resolvers"))
def test_runner_replaces_caller_resolver_override(flag):
    policy = SimpleNamespace(resolver_ips=("1.1.1.1",))
    argv = ("dnsx", "-duc", flag) if "=" in flag or flag.startswith("-system") else (
        "dnsx", "-duc", flag, "caller.txt",
    )
    request = runner_worker._configure_target_dns_resolvers(
        _request(argv), policy, SimpleNamespace(), ("127.0.0.1", 53053),
    )
    assert request.argv == ("dnsx", "-duc", "-r", "127.0.0.1:53053")
