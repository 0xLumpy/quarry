from __future__ import annotations

import errno
import fcntl
import json
import os
import signal
import socket
import ssl
import stat
import struct
import threading
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from quarry_recon import (
    config,
    evidence,
    fetch,
    netguard,
    network_broker,
    network_cdp,
    network_dns,
    network_policy,
    network_proxy,
    oos_regex,
    policy,
    sources,
)
from quarry_recon import cli as cli_mod
from quarry_recon.network_broker import (
    BrokerPolicy,
    NetworkBrokerRefused,
    NetworkEffectFence,
)
from quarry_recon.phases import params as params_phase


pytestmark = pytest.mark.offline


def _capture_fault(operation, faults) -> None:
    try:
        operation()
    except BaseException as exc:
        faults.append(exc)


def _sockaddr4(peer: str, port: int) -> bytes:
    return (
        struct.pack("=H", socket.AF_INET)
        + struct.pack("!H", port)
        + socket.inet_pton(socket.AF_INET, peer)
        + b"\x00" * 8
    )


def _sockaddr6(peer: str, port: int, *, flow: int = 0, scope: int = 0) -> bytes:
    return (
        struct.pack("=H", socket.AF_INET6)
        + struct.pack("!H", port)
        + struct.pack("=I", flow)
        + socket.inet_pton(socket.AF_INET6, peer)
        + struct.pack("=I", scope)
    )


def _policy(*, approved=("8.8.4.4",)) -> BrokerPolicy:
    return BrokerPolicy(
        "a" * 32,
        "probe.httpx",
        "httpx",
        False,
        (),
        ("192.0.2.10",),
        ("1.1.1.1",),
        ("example.test",),
        (),
        (),
        tuple(approved),
    )


def _control_policy(*, browser=False, controller=False) -> BrokerPolicy:
    identity = ("b" * 64, 1)
    return replace(
        _policy(),
        control_helpers=(identity,) if browser else (),
        control_clients=(identity,) if controller else (),
    )


def _cdp_fixture(*, fence, registry):
    chrome_output, chrome_output_peer = os.pipe2(os.O_CLOEXEC)
    chrome_input_peer, chrome_input = os.pipe2(os.O_CLOEXEC)
    bridge = network_cdp.PinnedCDPBridge(
        _control_policy(controller=True), registry,
        chrome_output_fd=chrome_output,
        chrome_input_fd=chrome_input,
        adapter="katana",
        controller_identity=("b" * 64, 1),
        expected_controller_tgid=123,
        deadline_monotonic=time.monotonic() + 5.0,
        effect_fence=fence,
    )
    return bridge, (
        chrome_output, chrome_output_peer, chrome_input_peer, chrome_input,
    )


def _native_scope(*, block_private=False):
    return network_policy.NetworkPolicyScope(
        block_private_targets=block_private,
        requested_cidrs=("10.0.0.0/24",),
        apex_domains=("example.test",),
        own_ips=("192.0.2.10",),
        resolver_ips=("1.1.1.1",),
    )


def _interface_snapshot(unicast=("192.0.2.10",), broadcasts=("255.255.255.255",)):
    return netguard.InterfaceSnapshot(tuple(unicast), tuple(broadcasts))


def test_transport_registry_is_exactly_source_keyed_and_complete():
    registered = network_policy.REGISTERED_TRANSPORT_DOORS
    assert set(registered) == set(policy.SOURCE_OWNERSHIP) == set(sources.all_sources())
    assert len(registered) == len(set(registered))
    for source_id, door in registered.items():
        assert door.source_id == source_id
        assert door.authority_class in network_policy.AUTHORITY_CLASSES
        assert bool(door.argv0) != bool(door.helpers) or source_id == "params.oob_probe"
        assert door.argv0 or door.helpers
        assert door.broker_required is bool(door.argv0)


def test_source_registry_backing_identity_matches_transport_authority():
    native_adapters = {
        "horizontal.csp", "horizontal.cloud_buckets", "crawl.js_fetch",
        "crawl.sourcemaps", "params.redirect_confirm", "probe.favicon", "probe.cert",
        "probe.shodan_host", "vertical.censys", "vertical.certspotter",
        "vertical.crtsh", "vertical.shosubgo", "horizontal.kaeferjaeger",
        "origin.correlation",
    }
    registry = sources.all_sources()
    for source_id, spec in registry.items():
        door = network_policy.REGISTERED_TRANSPORT_DOORS[source_id]
        if source_id in native_adapters:
            assert door.helpers and not door.argv0, source_id
        elif source_id == "params.oob_probe":
            assert door.helpers == ("fetch.redirect_location",)
            assert spec["tool"] in network_policy.AUXILIARY_TRANSPORT_DOORS[
                "params.oob_control"
            ].argv0
        elif source_id == "crawl.jxscout_ast":
            assert door.argv0 == ("systemd-run",) and not door.supported
        elif source_id == "crawl.jxscout_chunks":
            assert door.argv0 == ("bwrap",) and not door.supported
        else:
            assert spec["tool"] in door.argv0, (source_id, spec["tool"], door.argv0)


def test_transport_lookup_never_falls_back_to_a_tool_basename():
    assert network_policy.transport_door("ffuf", argv=("ffuf", "-u", "x")) is None
    assert network_policy.transport_door(
        "content.ffuf", argv=("katana", "-u", "https://example.test"),
    ) is None
    assert network_policy.transport_door(
        "content.ffuf", argv=("ffuf", "-u", "https://example.test"),
    ).profile == "content-ffuf"
    assert network_policy.transport_door(
        "probe.ffuf_vhost", argv=("ffuf", "-u", "https://example.test"),
    ).profile == "vhost-ffuf"


def test_transport_lookup_requires_exact_native_helper_identity():
    assert network_policy.transport_door(
        "horizontal.csp", helper="fetch.scoped_headers",
    ).profile == "native-target-http"
    assert network_policy.transport_door(
        "horizontal.csp", helper="fetch.scoped_get",
    ) is None
    assert network_policy.transport_door("horizontal.csp") is None


def test_provider_tools_do_not_inherit_target_private_authority():
    for source_id in (
        "vertical.subfinder", "horizontal.asnmap",
        "crawl.gau", "crawl.waymore_urls", "probe.smap", "enrich.smap",
    ):
        door = network_policy.REGISTERED_TRANSPORT_DOORS[source_id]
        assert door.authority_class == "public-provider", source_id
    assert network_policy.REGISTERED_TRANSPORT_DOORS["probe.smap"].kind == \
        "external-provider"
    caduceus = network_policy.REGISTERED_TRANSPORT_DOORS["horizontal.caduceus"]
    assert (caduceus.authority_class, caduceus.profile) == ("target", "target-cidr-tls")


def test_native_public_provider_host_and_peer_authority_are_both_exact(monkeypatch):
    scope = _native_scope(block_private=False)
    assert scope.host_allowed(
        "api.shodan.io", source_id="probe.shodan_host",
    )[0] == "allow"
    assert scope.host_allowed(
        "other.shodan.io", source_id="probe.shodan_host",
    )[0] == "deny"
    monkeypatch.setattr(netguard, "own_ips", lambda: ("192.0.2.10",))
    monkeypatch.setattr(netguard, "interface_snapshot", _interface_snapshot)
    provider = scope.decide_peer(
        "10.0.0.2", 443, socket.SOCK_STREAM, socket.IPPROTO_TCP,
        source_id="probe.shodan_host",
    )
    target = scope.decide_peer(
        "10.0.0.2", 443, socket.SOCK_STREAM, socket.IPPROTO_TCP,
        source_id="evidence.openapi",
    )
    assert provider.decision == "deny" and "public provider" in provider.reason
    assert target.decision == "allow"


def test_unknown_native_source_is_denied_before_authority_resolution():
    scope = _native_scope()
    assert scope.host_allowed(
        "example.test", source_id="native-http",
    ) == ("deny", "native HTTP source has no exact transport door")


def test_public_provider_mixed_safe_private_answer_refuses_as_one_set(monkeypatch):
    scope = _native_scope(block_private=False)
    monkeypatch.setattr(scope, "_trace", lambda _document: None)
    repository = SimpleNamespace(_network_policy_scope=scope)
    ctx = SimpleNamespace(
        run=repository,
        profile=SimpleNamespace(block_private_targets=False),
    )
    monkeypatch.setattr(
        network_dns, "resolve",
        lambda *_args, **_kwargs: (("8.8.8.8", "10.0.0.2"), "ok"),
    )
    monkeypatch.setattr(netguard, "interface_snapshot", _interface_snapshot)
    result = evidence.fetch._contact(
        ctx, "api.shodan.io", port=443, source_id="probe.shodan_host",
    )
    assert result[0] == "scope_refused"
    assert result.approved == ()
    assert result[1] == ["10.0.0.2"]


def test_bound_native_fetch_uses_only_literal_resolver_with_paired_trace(monkeypatch):
    scope = _native_scope(block_private=False)
    rows = []
    monkeypatch.setattr(
        scope, "trace_native_planned",
        lambda **row: rows.append(("planned", row)),
    )
    monkeypatch.setattr(
        scope, "trace_native_settled",
        lambda **row: rows.append(("settled", row)),
    )
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *_args, **_kwargs: pytest.fail("ambient NSS resolver was reached"),
    )

    def exact_resolve(policy_arg, host, *, on_event, **_kwargs):
        assert policy_arg.resolver_ips == ("1.1.1.1",)
        assert host == "example.test"
        on_event("dns-planned", "1.1.1.1", 53, "allow", "planned")
        on_event("dns-settled", "1.1.1.1", 53, "allow", "settled")
        return ("8.8.8.8",), "ok"

    monkeypatch.setattr(network_dns, "resolve", exact_resolve)
    result = evidence.fetch._explicit_contact(
        scope, "example.test", source_id="evidence.openapi",
        block_private=False,
    )
    assert result[0] == "contact" and result.approved == ("8.8.8.8",)
    assert [stage for stage, _row in rows] == ["planned", "settled"]
    assert rows[0][1]["request_id"] == rows[1][1]["request_id"]


def test_serialized_broker_semantics_are_source_derived_and_dns_is_mediator_only(
        monkeypatch):
    scope = _native_scope()
    document = scope.broker_policy(
        request_id="b" * 32, source_id="probe.httpx", tool="httpx",
        approved_peers=("8.8.8.8",),
    )
    assert {
        name: document[name]
        for name in (
            "authority_class", "transport_profile", "peer_mode", "resolver_mode",
        )
    } == {
        "authority_class": "target",
        "transport_profile": "target-http-proxy",
        "peer_mode": "deny-all",
        "resolver_mode": "mediated-public",
    }
    parsed = BrokerPolicy.from_json(json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ))
    monkeypatch.setattr(netguard, "own_ips", lambda: ("192.0.2.10",))
    monkeypatch.setattr(netguard, "interface_snapshot", _interface_snapshot)
    # The external HTTP child cannot use either the target or resolver directly;
    # only the trusted validating resolver and pinned proxy use mediated calls.
    assert parsed.decide(
        "8.8.8.8", 443, socket.SOCK_STREAM, socket.IPPROTO_TCP,
    )[0] == "deny"
    assert parsed.decide(
        "1.1.1.1", 53, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
    )[0] == "deny"
    assert parsed.decide_dns(
        "1.1.1.1", 53, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
    )[0] == "allow"


@pytest.mark.parametrize("field,value", [
    ("authority_class", "public-provider"),
    ("transport_profile", "public-provider"),
    ("peer_mode", "public-unicast"),
    ("resolver_mode", "none"),
])
def test_serialized_broker_semantics_cannot_be_rewritten_by_the_child(field, value):
    document = _native_scope().broker_policy(
        request_id="c" * 32, source_id="probe.httpx", tool="httpx",
        approved_peers=("8.8.8.8",),
    )
    document[field] = value
    with pytest.raises(NetworkBrokerRefused, match="policy_invalid"):
        BrokerPolicy.from_json(json.dumps(
            document, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ))


def test_public_provider_direct_policy_is_global_tcp_only_and_never_dns(
        monkeypatch):
    document = _native_scope().broker_policy(
        request_id="d" * 32, source_id="horizontal.asnmap", tool="asnmap",
        approved_peers=(),
    )
    parsed = BrokerPolicy.from_json(json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ))
    monkeypatch.setattr(netguard, "interface_snapshot", _interface_snapshot)
    assert parsed.decide(
        "8.8.8.8", 443, socket.SOCK_STREAM, socket.IPPROTO_TCP,
    )[0] == "allow"
    assert parsed.decide(
        "10.0.0.2", 443, socket.SOCK_STREAM, socket.IPPROTO_TCP,
    )[0] == "deny"
    assert parsed.decide(
        "8.8.8.8", 443, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
    )[0] == "deny"
    assert parsed.decide(
        "1.1.1.1", 53, socket.SOCK_STREAM, socket.IPPROTO_TCP,
    )[0] == "deny"


def test_resolver_snapshot_rejects_ipv6_zone_selection_before_effect(tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver fe80::53%eth0\n", encoding="ascii")
    with pytest.raises(network_policy.NetworkPolicyError, match="scope ids"):
        network_policy._resolver_snapshot(str(resolv))


def test_mediated_public_resolver_set_refuses_private_or_stub_addresses():
    for value in ("127.0.0.53", "10.0.0.53", "fe80::53"):
        with pytest.raises(network_policy.NetworkPolicyError,
                           match="non-public|unusable"):
            network_policy.NetworkPolicyScope(
                block_private_targets=False,
                apex_domains=("example.test",), own_ips=("192.0.2.10",),
                resolver_ips=(value,),
            )


def test_mediated_public_resolver_set_rejects_mixed_scoped_member():
    with pytest.raises(network_policy.NetworkPolicyError, match="invalid"):
        network_policy._public_resolvers(("1.1.1.1", "fe80::53%eth0"))


@pytest.mark.parametrize("value", [
    "0.0.0.0", "255.255.255.255", "224.0.0.1", "169.254.1.1", "::", "ff02::1",
])
def test_ambient_resolver_snapshot_rejects_non_unicast_special_use(value):
    with pytest.raises(network_policy.NetworkPolicyError, match="unusable"):
        network_policy._explicit_resolvers((value,))


def test_ambient_resolver_provenance_is_exact_dns_only_authority(monkeypatch):
    monkeypatch.setattr(
        network_policy, "_resolver_snapshot", lambda: ("127.0.0.53",),
    )
    scope = network_policy.NetworkPolicyScope(
        block_private_targets=False,
        apex_domains=("example.test",), own_ips=("192.0.2.10",),
    )
    assert scope.resolver_mode == "mediated-explicit"
    document = scope.broker_policy(
        request_id="e" * 32, source_id="probe.httpx", tool="httpx",
    )
    assert document["resolver_mode"] == "mediated-explicit"
    parsed = BrokerPolicy.from_json(json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ))
    monkeypatch.setattr(netguard, "interface_snapshot", _interface_snapshot)
    assert parsed.decide_dns(
        "127.0.0.53", 53, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
    )[0] == "allow"


def test_explicit_dns_never_treats_directed_broadcast_as_own_unicast(monkeypatch):
    policy_value = BrokerPolicy(
        "a" * 32, "probe.httpx", "httpx", False, (),
        ("10.203.0.2", "10.203.0.255"), ("10.203.0.255",),
        ("example.test",), (), (), (), resolver_mode="mediated-explicit",
    )
    monkeypatch.setattr(
        netguard, "interface_snapshot",
        lambda: _interface_snapshot(
            ("10.203.0.2",), ("255.255.255.255", "10.203.0.255"),
        ),
    )
    assert policy_value.decide_dns(
        "10.203.0.255", 53, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
    )[0] == "deny"


@pytest.mark.parametrize("resolver", ["127.0.0.53", "10.203.0.53"])
def test_explicit_dns_keeps_loopback_and_private_unicast_authority(
        monkeypatch, resolver):
    policy_value = BrokerPolicy(
        "a" * 32, "probe.httpx", "httpx", False, (),
        ("10.203.0.2",), (resolver,), ("example.test",), (), (), (),
        resolver_mode="mediated-explicit",
    )
    monkeypatch.setattr(
        netguard, "interface_snapshot",
        lambda: _interface_snapshot(
            ("10.203.0.2",), ("255.255.255.255", "10.203.0.255"),
        ),
    )
    assert policy_value.decide_dns(
        resolver, 53, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
    )[0] == "allow"


@pytest.mark.parametrize("resolver,broadcasts,expected", [
    ("10.203.1.255", ("10.203.255.255",), "allow"),
    ("10.203.255.255", ("10.203.255.255",), "deny"),
    ("10.203.0.127", ("10.203.0.127",), "deny"),
])
def test_explicit_dns_uses_exact_tagged_broadcast_snapshot(
        monkeypatch, resolver, broadcasts, expected):
    policy_value = BrokerPolicy(
        "a" * 32, "probe.httpx", "httpx", False, (),
        ("10.203.1.2",), (resolver,), ("example.test",), (), (), (),
        resolver_mode="mediated-explicit",
    )
    calls = []

    def snapshot():
        calls.append(True)
        return _interface_snapshot(("10.203.1.2",), broadcasts)

    monkeypatch.setattr(netguard, "interface_snapshot", snapshot)
    assert policy_value.decide_dns(
        resolver, 53, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
    )[0] == expected
    assert calls == [True]


@pytest.mark.parametrize("address,mask", [
    ("10.0.0.0", "255.255.255.254"),
    ("10.0.0.1", "255.255.255.255"),
])
def test_slash31_and_slash32_interfaces_have_no_directed_broadcast(address, mask):
    with pytest.raises(OSError, match="no directed broadcast"):
        netguard._directed_broadcast(address, mask)


def test_oos_grammar_is_shared_and_rejects_backtracking_constructs():
    unsafe = r"(a+)+$"
    with pytest.raises(oos_regex.OOSRegexError):
        oos_regex.compile_oos(unsafe)
    with pytest.raises(network_policy.NetworkPolicyError,
                       match="out-of-scope pattern"):
        network_policy.NetworkPolicyScope(
            block_private_targets=False,
            apex_domains=("example.test",), oos_patterns=(unsafe,),
            own_ips=("192.0.2.10",), resolver_ips=("1.1.1.1",),
        )
    document = _native_scope().broker_policy(
        request_id="f" * 32, source_id="probe.httpx", tool="httpx",
    )
    document["oos_patterns"] = [unsafe]
    with pytest.raises(NetworkBrokerRefused, match="policy_invalid"):
        BrokerPolicy.from_json(json.dumps(
            document, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ))


def test_scope_matcher_never_runs_regex_on_oversized_discovered_text():
    class RawWitness:
        flags = 0

        def search(self, _value):
            pytest.fail("oversized attacker text reached the regex engine")

    bounded = oos_regex.BoundedOOSPattern(r"a+", RawWitness())
    matcher = config.ScopeMatcher(
        ["example.test"], [bounded], [], False,
    )
    assert matcher.is_oos("a" * 100_000 + ".example.test") is False


@pytest.mark.parametrize("host", [
    "example.test\n", ".example.test", "example.test.", "exam\x01ple.test",
    "a" * 64 + ".example.test", "a" * 254,
])
def test_oos_engine_refuses_noncanonical_host_text_before_regex(host):
    class RawWitness:
        flags = 0

        def search(self, _value):
            pytest.fail("noncanonical attacker text reached the regex engine")

    bounded = oos_regex.BoundedOOSPattern(r"example", RawWitness())
    assert bounded.search(host) is None
    with pytest.raises(oos_regex.OOSRegexError, match="not canonical"):
        oos_regex.oos_search(r"example", host)


def test_oos_cli_never_persists_a_pattern_the_loader_refuses(tmp_path):
    profile = tmp_path / "target.yaml"
    profile.write_text(
        "TARGET: example\nAPEX_DOMAINS:\n  - example.com\nOOS:\n",
        encoding="utf-8",
    )
    original = profile.read_bytes()
    result = CliRunner().invoke(
        cli_mod.cli, ["oos", "-t", str(profile), "(foo|bar)"],
    )
    assert result.exit_code != 0
    assert "not admitted" in result.output
    assert profile.read_bytes() == original

    accepted = CliRunner().invoke(
        cli_mod.cli, ["oos", "-t", str(profile), "*.partner.example.com"],
    )
    assert accepted.exit_code == 0, accepted.output
    loaded = config.TargetProfile.load(profile)
    loaded.scope()
    assert loaded.oos == [r"^.*\.partner\.example\.com$"]


def _dns_rr(owner: str, kind: int, body: bytes) -> bytes:
    return (
        network_dns._encode_name(owner)
        + struct.pack("!HHIH", kind, 1, 60, len(body)) + body
    )


def _dns_response(host: str, query_type: int, transaction: int, *,
                  answers=(), authority=(), additional=(), rcode=0) -> bytes:
    return (
        network_dns._DNS_HEADER.pack(
            transaction, 0x8180 | rcode, 1,
            len(answers), len(authority), len(additional),
        )
        + network_dns._encode_name(host) + struct.pack("!HH", query_type, 1)
        + b"".join(answers) + b"".join(authority) + b"".join(additional)
    )


def test_dns_additional_and_authority_records_never_supply_an_answer():
    host = "victim.example"
    transaction = 7
    poison = _dns_rr(host, 1, socket.inet_pton(socket.AF_INET, "8.8.8.8"))
    for field in ("authority", "additional"):
        message = _dns_response(
            host, 1, transaction, **{field: (poison,)},
        )
        assert network_dns._parse_response(
            message, transaction=transaction, host=host, query_type=1,
        ) == ((), None, "nodata")


def test_dns_same_owner_cname_and_address_rrset_is_malformed():
    host = "victim.example"
    message = _dns_response(
        host, 1, 8,
        answers=(
            _dns_rr(host, 5, network_dns._encode_name("other.example")),
            _dns_rr(host, 1, socket.inet_pton(socket.AF_INET, "8.8.8.8")),
        ),
    )
    with pytest.raises(network_dns.NetworkDNSRefused, match="malformed"):
        network_dns._parse_response(
            message, transaction=8, host=host, query_type=1,
        )


@pytest.mark.parametrize("query_type,address_type,address", [
    (1, 28, "2606:4700:4700::1111"),
    (28, 1, "8.8.8.8"),
])
def test_dns_cname_cannot_coexist_with_other_address_family(
        query_type, address_type, address):
    host = "victim.example"
    family = socket.AF_INET if address_type == 1 else socket.AF_INET6
    message = _dns_response(
        host, query_type, 9,
        answers=(
            _dns_rr(host, 5, network_dns._encode_name("other.example")),
            _dns_rr(host, address_type, socket.inet_pton(family, address)),
        ),
    )
    with pytest.raises(network_dns.NetworkDNSRefused, match="malformed"):
        network_dns._parse_response(
            message, transaction=9, host=host, query_type=query_type,
        )


def test_dns_forward_compression_pointer_cannot_borrow_later_section_bytes():
    with pytest.raises(network_dns.NetworkDNSRefused, match="malformed"):
        network_dns._decode_name(b"\xc0\x02\x00", 0)


@pytest.mark.parametrize("states,expected", [
    ({1: (("8.8.8.8",), "ok"), 28: ((), "timeout")},
     ((), "indeterminate")),
    ({1: ((), "malformed"), 28: (("2606:4700:4700::1111",), "ok")},
     ((), "indeterminate")),
    ({1: (("8.8.8.8",), "ok"), 28: ((), "nodata")},
     (("8.8.8.8",), "ok")),
    ({1: ((), "nxdomain"), 28: ((), "nxdomain")},
     ((), "nxdomain")),
    ({1: ((), "nxdomain"), 28: ((), "nodata")},
     ((), "indeterminate")),
])
def test_dns_address_families_settle_all_or_nothing(monkeypatch, states, expected):
    def exchange(_policy_arg, _resolver, request, **_kwargs):
        query_type = struct.unpack("!H", request[-4:-2])[0]
        if states[query_type][1] == "timeout":
            raise TimeoutError("fixture timeout")
        return bytes((query_type,))

    def parse(_response, *, query_type, **_kwargs):
        answers, state = states[query_type]
        if state == "malformed":
            raise network_dns.NetworkDNSRefused("fixture malformed")
        return answers, None, state

    monkeypatch.setattr(network_dns, "_exchange", exchange)
    monkeypatch.setattr(network_dns, "_parse_response", parse)
    assert network_dns.resolve(_policy(), "example.test") == expected


def test_dns_socket_constructor_failure_has_one_terminal_event(monkeypatch):
    events_seen = []
    monkeypatch.setattr(netguard, "own_ips", lambda: ("192.0.2.10",))
    monkeypatch.setattr(
        network_dns.socket, "socket",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("fixture")),
    )
    with pytest.raises(OSError, match="fixture"):
        network_dns._exchange(
            _policy(), "1.1.1.1", network_dns._wire_query("example.test", 1, 10),
            deadline_monotonic=time.monotonic() + 1, transaction=10,
            on_event=lambda *row: events_seen.append(row),
            effect_fence=NetworkEffectFence(),
        )
    assert [row[0] for row in events_seen] == ["dns-planned", "dns-settled"]
    assert events_seen[-1][3] == "deny"


def test_dns_fence_closed_track_failure_has_one_terminal_event(monkeypatch):
    events_seen = []
    monkeypatch.setattr(netguard, "own_ips", lambda: ("192.0.2.10",))
    fence = NetworkEffectFence()
    fence.cancel()
    with pytest.raises(NetworkBrokerRefused, match="fence_closed"):
        network_dns._exchange(
            _policy(), "1.1.1.1", network_dns._wire_query("example.test", 1, 11),
            deadline_monotonic=time.monotonic() + 1, transaction=11,
            on_event=lambda *row: events_seen.append(row), effect_fence=fence,
        )
    assert [row[0] for row in events_seen] == ["dns-planned", "dns-settled"]
    assert events_seen[-1][3] == "deny"


def test_dns_trace_callback_fault_cancels_shared_fence_before_return(monkeypatch):
    transaction = 12
    response = _dns_response(
        "example.test", 1, transaction,
        answers=(_dns_rr(
            "example.test", 1, socket.inet_pton(socket.AF_INET, "8.8.8.8"),
        ),),
    )

    class ResponseSocket(socket.socket):
        def getpeername(self):
            return "1.1.1.1", 53

        def recv(self, _size):
            return response

    monkeypatch.setattr(netguard, "interface_snapshot", _interface_snapshot)
    monkeypatch.setattr(network_dns.socket, "socket", ResponseSocket)
    monkeypatch.setattr(network_dns, "_connect", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(network_dns, "_send_all", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(network_dns, "_wait", lambda *_args, **_kwargs: None)
    fence = NetworkEffectFence()

    def event(stage, *_args):
        if stage == "dns-settled":
            raise RuntimeError("durable terminal fault")

    with pytest.raises(RuntimeError, match="durable terminal fault"):
        network_dns._exchange(
            _policy(), "1.1.1.1",
            network_dns._wire_query("example.test", 1, transaction),
            deadline_monotonic=time.monotonic() + 1, transaction=transaction,
            on_event=event, effect_fence=fence,
        )
    assert fence.is_set()
    with pytest.raises(NetworkBrokerRefused, match="fence_closed"):
        with fence:
            pytest.fail("sibling effect entered after trace failure")


def _install_dns_scenario(monkeypatch, scenario):
    def exchange(_policy_arg, _resolver, request, *, transaction, **_kwargs):
        queried, offset = network_dns._decode_name(request, network_dns._DNS_HEADER.size)
        query_type = struct.unpack_from("!H", request, offset)[0]
        answers, rcode = scenario(queried, query_type)
        return _dns_response(
            queried, query_type, transaction, answers=answers, rcode=rcode,
        )

    monkeypatch.setattr(network_dns, "_exchange", exchange)


def test_dns_family_obligations_require_the_same_cname_chain(monkeypatch):
    def scenario(host, query_type):
        if query_type == 1:
            return (
                _dns_rr(host, 5, network_dns._encode_name("alias.example")),
                _dns_rr(
                    "alias.example", 1,
                    socket.inet_pton(socket.AF_INET, "8.8.8.8"),
                ),
            ), 0
        return (
            _dns_rr(
                host, 28,
                socket.inet_pton(socket.AF_INET6, "2606:4700:4700::1111"),
            ),
        ), 0

    _install_dns_scenario(monkeypatch, scenario)
    assert network_dns.resolve(_policy(), "example.test") == ((), "indeterminate")


def test_dns_identical_cname_chain_accepts_address_plus_nodata(monkeypatch):
    def scenario(host, query_type):
        if host == "example.test":
            answers = [
                _dns_rr(host, 5, network_dns._encode_name("alias.example")),
            ]
            if query_type == 1:
                answers.append(_dns_rr(
                    "alias.example", 1,
                    socket.inet_pton(socket.AF_INET, "8.8.8.8"),
                ))
            return tuple(answers), 0
        assert host == "alias.example" and query_type == 28
        return (), 0

    _install_dns_scenario(monkeypatch, scenario)
    assert network_dns.resolve(_policy(), "example.test") == \
        (("8.8.8.8",), "ok")


def test_dns_global_cname_graph_rejects_hidden_intermediate_conflict(monkeypatch):
    def scenario(host, query_type):
        if host == "example.test":
            return (
                _dns_rr(host, 5, network_dns._encode_name("a.example")),
                _dns_rr("a.example", 5, network_dns._encode_name("b.example")),
            ), 0
        if host == "b.example":
            return (
                _dns_rr("a.example", 5, network_dns._encode_name("c.example")),
                _dns_rr("b.example", 5, network_dns._encode_name("d.example")),
            ), 0
        return (), 0

    _install_dns_scenario(monkeypatch, scenario)
    assert network_dns.resolve(_policy(), "example.test") == ((), "indeterminate")


def test_dns_multi_hop_answer_continues_at_its_unresolved_endpoint(monkeypatch):
    def scenario(host, query_type):
        if host == "example.test":
            return (
                _dns_rr(host, 5, network_dns._encode_name("a.example")),
                _dns_rr("a.example", 5, network_dns._encode_name("b.example")),
            ), 0
        assert host == "b.example"
        if query_type == 1:
            return (_dns_rr(
                host, 1, socket.inet_pton(socket.AF_INET, "8.8.8.8"),
            ),), 0
        return (), 0

    _install_dns_scenario(monkeypatch, scenario)
    assert network_dns.resolve(_policy(), "example.test") == \
        (("8.8.8.8",), "ok")


@pytest.mark.parametrize("links,expected_state", [(8, "ok"), (9, "indeterminate")])
def test_dns_cname_link_budget_is_global_across_responses(
        monkeypatch, links, expected_state):
    names = ["example.test", *(f"n{index}.example" for index in range(links))]

    def scenario(host, query_type):
        index = names.index(host)
        if index < links:
            return (_dns_rr(
                host, 5, network_dns._encode_name(names[index + 1]),
            ),), 0
        if query_type == 1:
            return (_dns_rr(
                host, 1, socket.inet_pton(socket.AF_INET, "8.8.8.8"),
            ),), 0
        return (), 0

    _install_dns_scenario(monkeypatch, scenario)
    answers, state = network_dns.resolve(_policy(), "example.test")
    assert state == expected_state
    assert answers == (("8.8.8.8",) if state == "ok" else ())


def test_update_capable_tools_require_the_disable_update_flag():
    cases = {
        "vertical.subfinder": ("subfinder", "-all"),
        "horizontal.asnmap": ("asnmap", "-silent"),
        "horizontal.mapcidr": ("mapcidr", "-silent"),
        "vertical.alterx_permute": ("alterx", "-silent"),
        "dns.dnsx_records": ("dnsx", "-silent"),
        "probe.httpx": ("httpx", "-silent"),
        "probe.tlsx_certs": ("tlsx", "-silent"),
        "crawl.katana_standard": ("katana", "-silent"),
        "params.oob_control": ("interactsh-client", "-json"),
    }
    for source_id, argv in cases.items():
        assert network_policy.transport_door(source_id, argv=argv) is None, source_id
        assert network_policy.transport_door(
            source_id, argv=(*argv, "-duc"),
        ) is not None, source_id


def test_naabu_is_connect_scan_only_under_the_transport_boundary():
    base = ("naabu", "-list", "targets.txt", "-duc", "-scan-type")
    assert network_policy.transport_door("probe.naabu_web", argv=(*base, "s")) is None
    assert network_policy.transport_door("probe.naabu_web", argv=(*base, "c")) is not None


def test_trufflehog_verification_is_not_misclassified_as_offline():
    base = ("trufflehog", "filesystem", "evidence", "--json", "--no-update")
    assert network_policy.transport_door("crawl.trufflehog", argv=base) is None
    offline = network_policy.transport_door(
        "crawl.trufflehog", argv=(*base, "--no-verification"),
    )
    assert offline is not None
    assert (offline.authority_class, offline.profile) == ("offline", "deny-all")


def test_auxiliary_transport_exception_set_is_exact():
    assert set(network_policy.AUXILIARY_TRANSPORT_DOORS) == {
        "evidence.exposed_fetch", "evidence.graphql_introspect",
        "evidence.actuator_probe", "evidence.deep_evidence", "evidence.openapi",
        "evidence.framework_probe", "evidence.ssti_probe", "osint.asrank",
        "osint.azmap", "osint.whoxy", "osint.rdap", "osint.asnmap",
        "osint.porch_pirate", "osint.whois", "osint.dmarc", "notify.slack",
        "notify.discord", "notify.telegram", "notify.webhook", "probe.cdncheck",
        "params.oob_control",
    }


def test_oob_control_and_target_probe_have_disjoint_effect_authorities():
    assert network_policy.transport_door(
        "params.oob_control", argv=("interactsh-client", "-duc", "-json"),
    ).authority_class == "operator-infrastructure"
    target = network_policy.transport_door(
        "params.oob_probe", helper="fetch.redirect_location",
    )
    assert (target.authority_class, target.profile) == ("target", "native-no-redirect")
    assert network_policy.transport_door(
        "params.oob_probe", argv=("interactsh-client", "-duc", "-json"),
    ) is None


def test_redirect_confirm_binds_its_exact_native_transport_source(monkeypatch):
    seen = []
    monkeypatch.setattr(
        params_phase.fetch, "redirect_location",
        lambda *_args, **kwargs: (seen.append(kwargs.get("source_id")) or (None, 200)),
    )
    for name in ("tool_start", "tool_progress", "tool_finish"):
        monkeypatch.setattr(params_phase.events, name, lambda *_args, **_kwargs: None)
    ctx = SimpleNamespace(
        scope=SimpleNamespace(active_allowed=lambda _host: True),
        run=SimpleNamespace(add=lambda *_args, **_kwargs: True),
    )
    params_phase._redirect_confirm(
        ctx, ["https://example.test/?redirect=https%3A%2F%2Fold.test"],
        SimpleNamespace(),
    )
    assert seen == ["params.redirect_confirm"]


def test_oob_target_probe_binds_native_source_separately_from_control(
        monkeypatch):
    seen = []
    monkeypatch.setattr(params_phase, "have", lambda _tool: True)
    monkeypatch.setattr(
        params_phase, "active_review_values",
        lambda *_args: ["https://example.test/?url=old"],
    )
    monkeypatch.setattr(
        params_phase, "_canonicalize_candidates",
        lambda values: (list(values), list(values)),
    )
    monkeypatch.setattr(params_phase.nuclei_policy, "policy_for", lambda _ctx: None)
    monkeypatch.setattr(params_phase.secrets, "oob", lambda: {})
    monkeypatch.setattr(
        params_phase.nuclei_policy, "_freeze_oob_config",
        lambda _value: {"callback_server": None, "auth_token": None},
    )
    session = {"log": "fixture"}
    monkeypatch.setattr(
        params_phase.oob, "open_session", lambda *_args, **_kwargs: (session, object()),
    )
    monkeypatch.setattr(params_phase.oob, "issue_token", lambda *_args, **_kwargs: "token")
    monkeypatch.setattr(
        params_phase.oob, "callback_url", lambda *_args, **_kwargs: "http://callback.test/x",
    )
    monkeypatch.setattr(params_phase.oob, "poll_session", lambda *_args: ())
    monkeypatch.setattr(params_phase.oob, "close_session", lambda *_args: None)
    monkeypatch.setattr(params_phase.time, "sleep", lambda _seconds: None)
    for name in ("emit", "tool_start", "tool_progress", "tool_finish", "ledger"):
        monkeypatch.setattr(params_phase.events, name, lambda *_args, **_kwargs: None)
    monkeypatch.setattr(params_phase.events, "work_unit", lambda *_args, **_kwargs: "wu")
    monkeypatch.setattr(
        params_phase.fetch, "redirect_location",
        lambda *_args, **kwargs: (seen.append(kwargs.get("source_id")) or (None, 200)),
    )

    class Run:
        def record(self, *_args, **_kwargs):
            return None

        def add(self, *_args, **_kwargs):
            return True

    ctx = SimpleNamespace(run=Run(), echo=lambda _value: None)
    params_phase._oob_probe(
        ctx, SimpleNamespace(passive_only=False), SimpleNamespace(oob_enabled=True),
    )
    assert seen == ["params.oob_probe"]


def test_existing_jxscout_wrapper_escapes_are_declared_but_never_admitted():
    ast = network_policy.REGISTERED_TRANSPORT_DOORS["crawl.jxscout_ast"]
    chunks = network_policy.REGISTERED_TRANSPORT_DOORS["crawl.jxscout_chunks"]
    assert not ast.supported and "systemd-run" in ast.unsupported_reason
    assert not chunks.supported and "pre-filter launcher" in chunks.unsupported_reason
    assert network_policy.transport_door(
        "crawl.jxscout_ast", argv=("systemd-run", "--user", "--scope"),
    ) is None
    assert network_policy.transport_door(
        "crawl.jxscout_chunks", argv=("bwrap", "--unshare-all"),
    ) is None


def test_evidence_acquisition_binds_semantic_source_before_transport(monkeypatch, tmp_path):
    seen = []

    def fake_fetch(*args, **kwargs):
        seen.append(kwargs["source_id"])
        return None, args[1], 0

    monkeypatch.setattr(evidence.fetch, "scoped_get_file", fake_fetch)
    result = evidence.acquire(
        object(), "https://example.test/a", tmp_path / "body", "example.test",
        source="openapi",
    )
    assert result == (None, "https://example.test/a", 0)
    assert seen == ["evidence.openapi"]
    with pytest.raises(ValueError, match="no network authority"):
        evidence.acquire(
            object(), "https://example.test/b", tmp_path / "body2", "example.test",
            source="new-ambient-caller",
        )
    assert seen == ["evidence.openapi"]


class _StopWitness:
    def __init__(self):
        self.called = 0

    def set(self):
        self.called += 1


def _recording_session():
    session = network_broker.NetworkBrokerSession.__new__(
        network_broker.NetworkBrokerSession,
    )
    session._records_lock = threading.Lock()
    session._records = []
    session._open_plans = {}
    session._dropped = 0
    session._fatal = None
    session._stop = _StopWitness()
    return session


def test_effect_fence_signals_before_waiting_and_closes_tracked_planes():
    fence = NetworkEffectFence()
    tracked, witness = socket.socketpair()
    fence.track_socket(tracked)
    entered = threading.Event()

    def in_flight_effect() -> None:
        with fence:
            entered.set()
            assert fence.event.wait(1)

    worker = threading.Thread(target=in_flight_effect)
    worker.start()
    assert entered.wait(1)
    started = time.monotonic()
    fence.cancel()
    assert time.monotonic() - started < 1
    worker.join(1)
    assert not worker.is_alive()
    witness.settimeout(1)
    assert witness.recv(1) == b""
    witness.close()
    assert fence.is_set()


def test_effect_fence_atomically_replaces_a_detached_socket_owner():
    fence = NetworkEffectFence()
    raw, witness = socket.socketpair()
    fence.track_socket(raw)
    live = socket.socket(fileno=raw.detach())
    assert raw.fileno() == -1
    with fence:
        fence.replace_tracked_socket(raw, live)
    fence.cancel()
    assert live.fileno() == -1
    assert witness.recv(1) == b""
    witness.close()


def test_native_tls_cancellation_tracks_the_live_ssl_socket_not_detached_raw():
    fence = NetworkEffectFence()
    transport = fetch._PinnedTransport((), effect_fence=fence)
    raw, witness = socket.socketpair()
    raw.settimeout(5.0)
    transport._track(raw)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    outcome = []

    def handshake():
        try:
            transport.wrap_tls(raw, context, server_hostname="fixture.test")
        except BaseException as exc:
            outcome.append(exc)

    worker = threading.Thread(target=handshake)
    worker.start()
    deadline = time.monotonic() + 1.0
    while raw.fileno() != -1 and time.monotonic() < deadline:
        time.sleep(0.001)
    assert raw.fileno() == -1
    # Tracking only ``raw`` would close EBADF and leave the TLS data plane
    # alive until its five-second timeout.  Cancellation owns the replacement.
    fence.cancel()
    worker.join(1.0)
    assert not worker.is_alive()
    assert outcome
    assert transport._connections == set()
    witness.settimeout(1.0)
    while witness.recv(4096):
        pass
    witness.close()


def test_native_transport_close_remains_inside_fence_until_fd_is_closed():
    entered = threading.Event()
    release = threading.Event()

    class BlockingCloseSocket(socket.socket):
        def shutdown(self, how):
            entered.set()
            assert release.wait(1.0)
            return super().shutdown(how)

    original, witness = socket.socketpair()
    tracked = BlockingCloseSocket(fileno=original.detach())
    fence = NetworkEffectFence()
    transport = fetch._PinnedTransport((), effect_fence=fence)
    transport._track(tracked)
    closer = threading.Thread(target=transport.release)
    closer.start()
    assert entered.wait(1.0)
    cancelled = threading.Event()

    def cancel():
        fence.cancel()
        cancelled.set()

    canceller = threading.Thread(target=cancel)
    canceller.start()
    # cancel() signals first but cannot acknowledge until the in-fence close
    # has completed; there is no untracked-yet-live interval.
    assert fence.event.wait(1.0)
    assert not cancelled.wait(0.05)
    release.set()
    closer.join(1.0)
    canceller.join(1.0)
    assert not closer.is_alive() and not canceller.is_alive()
    assert cancelled.is_set() and tracked.fileno() == -1
    assert transport._connections == set()
    witness.settimeout(1.0)
    assert witness.recv(1) == b""
    witness.close()


def test_native_http_request_write_is_a_cancellable_fenced_effect():
    entered = threading.Event()
    release = threading.Event()

    class BlockingSendSocket(socket.socket):
        def send(self, body, *args, **kwargs):
            entered.set()
            assert release.wait(1.0)
            return super().send(body, *args, **kwargs)

    original, witness = socket.socketpair()
    tracked = BlockingSendSocket(fileno=original.detach())
    tracked.settimeout(1.0)
    fence = NetworkEffectFence()
    transport = fetch._PinnedTransport((), effect_fence=fence)
    transport._track(tracked)
    outcome = []

    def sender():
        try:
            transport.send_all(tracked, b"x")
        except BaseException as exc:
            outcome.append(exc)

    worker = threading.Thread(target=sender)
    worker.start()
    assert entered.wait(1.0)
    cancelled = threading.Event()

    def cancel():
        fence.cancel()
        cancelled.set()

    canceller = threading.Thread(target=cancel)
    canceller.start()
    assert fence.event.wait(1.0)
    assert not cancelled.wait(0.05)
    release.set()
    worker.join(1.0)
    canceller.join(1.0)
    assert not worker.is_alive() and not canceller.is_alive()
    assert cancelled.is_set() and not outcome and tracked.fileno() == -1
    witness.settimeout(1.0)
    assert witness.recv(2) == b"x"
    assert witness.recv(1) == b""
    witness.close()


def test_native_http_response_read_is_a_cancellable_fenced_effect():
    entered = threading.Event()
    release = threading.Event()

    class ReadCanWriteProtocolBytes:
        def readinto(self, buffer):
            entered.set()
            assert release.wait(1.0)
            buffer[:1] = b"x"
            return 1

    tracked, witness = socket.socketpair()
    tracked.settimeout(1.0)
    fence = NetworkEffectFence()
    transport = fetch._PinnedTransport((), effect_fence=fence)
    transport._track(tracked)
    outcome = []

    def reader():
        try:
            outcome.append(transport.read_into(
                tracked, ReadCanWriteProtocolBytes().readinto,
                bytearray(1), 1.0,
            ))
        except BaseException as exc:
            outcome.append(exc)

    worker = threading.Thread(target=reader)
    worker.start()
    assert entered.wait(1.0)
    cancelled = threading.Event()
    canceller = threading.Thread(
        target=lambda: (fence.cancel(), cancelled.set()),
    )
    canceller.start()
    assert fence.event.wait(1.0)
    assert not cancelled.wait(0.05)
    release.set()
    worker.join(1.0)
    canceller.join(1.0)
    assert outcome == [1]
    assert cancelled.is_set() and tracked.fileno() == -1
    witness.close()


def test_response_cleanup_fenced_releases_transport_before_file_close():
    order = []

    class Transport:
        def release(self):
            order.append("release")

    class Response:
        _quarry_network_transport = Transport()

        def close(self):
            order.append("close")

    with fetch._response_lifetime(Response()):
        order.append("body")
    assert order == ["body", "release", "close"]


def test_uncertain_socket_close_remains_tracked_until_retry():
    class FailOnceCloseSocket(socket.socket):
        attempts = 0

        def close(self):
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("fixture close fault")
            return super().close()

    original, witness = socket.socketpair()
    tracked = FailOnceCloseSocket(fileno=original.detach())
    fence = NetworkEffectFence()
    fence.track_socket(tracked)
    with pytest.raises(NetworkBrokerRefused, match="socket_close_failed"):
        fence.close_tracked_socket(tracked)
    assert tracked.fileno() >= 0 and tracked in fence._sockets and fence.is_set()
    fence.cancel()
    assert tracked.fileno() == -1 and tracked not in fence._sockets
    witness.close()


def test_oversized_tracee_executable_is_refused_before_reading_its_body(monkeypatch):
    monkeypatch.setattr(network_broker.os, "open", lambda *_args, **_kwargs: 91)
    monkeypatch.setattr(
        network_broker.os, "fstat",
        lambda _fd: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o500,
            st_size=network_broker._MAX_EXECUTABLE_BYTES + 1,
        ),
    )
    monkeypatch.setattr(
        network_broker.os, "read",
        lambda *_args, **_kwargs: pytest.fail("oversize executable body was read"),
    )
    monkeypatch.setattr(network_broker.os, "close", lambda _fd: None)
    with pytest.raises(NetworkBrokerRefused, match="helper_identity_failed"):
        network_broker._hash_tracee_executable(
            7, validate=lambda: None,
            deadline_monotonic=time.monotonic() + 1.0,
        )


def test_stable_executable_stamp_is_hashed_once_across_tracee_tids(monkeypatch):
    session = network_broker.NetworkBrokerSession.__new__(
        network_broker.NetworkBrokerSession,
    )
    session._stop = threading.Event()
    session._identity_lock = threading.Lock()
    session._executable_cache = {}
    session._deadline = time.monotonic() + 2.0
    session._require_valid = lambda _identifier: None
    executable = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o500, st_size=1234,
        st_dev=11, st_ino=22, st_mtime_ns=33, st_ctime_ns=44,
    )
    monkeypatch.setattr(network_broker.os, "open", lambda *_args, **_kwargs: 91)
    monkeypatch.setattr(network_broker.os, "fstat", lambda _fd: executable)
    monkeypatch.setattr(network_broker.os, "close", lambda _fd: None)
    identity = ("a" * 64, executable.st_size)
    calls = []

    def hash_once(tid, **_kwargs):
        calls.append(tid)
        return identity

    monkeypatch.setattr(network_broker, "_hash_tracee_executable", hash_once)
    allowed = (identity,)
    assert session._tracee_identity(101, 1, allowed) == identity
    assert session._tracee_identity(202, 2, allowed) == identity
    assert calls == [101]


def test_pinned_httpconnection_send_uses_transport_fence(monkeypatch):
    opener, transport = fetch._pinned_opener(("8.8.8.8",))
    handler = next(
        item for item in opener.handlers
        if type(item).__module__ == fetch.__name__ and hasattr(item, "http_open")
    )
    classes = []
    monkeypatch.setattr(
        handler, "do_open", lambda connection_class, _request: classes.append(connection_class),
    )
    handler.http_open(fetch.urllib.request.Request("http://example.test/"))
    assert len(classes) == 1
    connection = classes[0]("example.test")
    live = object()
    connection.sock = live
    seen = []
    monkeypatch.setattr(
        transport, "send_all",
        lambda handle, body: seen.append((handle, bytes(body))),
    )
    connection.send(b"request")
    assert seen == [(live, b"request")]
    assert connection.sock is live


@pytest.mark.parametrize("response_bytes", [
    (
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n"
        b"Connection: close\r\n\r\nbody"
    ),
    b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody",
    b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody",
])
def test_stdlib_early_connection_close_retains_fenced_response_body(
        monkeypatch, response_bytes):
    fence = NetworkEffectFence()
    opener, transport = fetch._pinned_opener(
        ("8.8.8.8",), effect_fence=fence,
    )
    handler = next(
        item for item in opener.handlers
        if type(item).__module__ == fetch.__name__ and hasattr(item, "http_open")
    )
    classes = []
    monkeypatch.setattr(
        handler, "do_open",
        lambda connection_class, _request: classes.append(connection_class),
    )
    handler.http_open(fetch.urllib.request.Request("http://example.test/"))
    connection = classes[0]("example.test", timeout=1.0)
    live, server = socket.socketpair()
    live.settimeout(1.0)
    server.settimeout(1.0)
    connection.sock = live
    transport._track(live)
    server_faults = []

    def respond():
        try:
            request = bytearray()
            while b"\r\n\r\n" not in request:
                request.extend(server.recv(4096))
            server.sendall(response_bytes)
        except BaseException as exc:
            server_faults.append(exc)
        finally:
            server.close()

    worker = threading.Thread(target=respond)
    worker.start()
    connection.request("GET", "/")
    response = connection.getresponse()
    if connection.sock is not None:
        # Mirror urllib's persistent-response cleanup branch.  The installed
        # FencedSocket relinquishes connection ownership without closing the
        # transport that the response reader still needs.
        connection.sock.close()
        connection.sock = None
    assert response.read() == b"body"
    worker.join(1.0)
    assert not worker.is_alive() and not server_faults
    assert live in transport._connections and live in fence._sockets
    assert live.fileno() >= 0 and not fence.is_set()
    transport.release()
    assert live.fileno() == -1
    response.close()


@pytest.mark.parametrize("headers", [
    {"Host": "oos.example"}, {":authority": "oos.example"},
    {"Proxy-Authorization": "secret"}, {"Proxy-Connection": "keep-alive"},
])
def test_native_request_headers_cannot_override_url_authority(monkeypatch, headers):
    monkeypatch.setattr(
        fetch, "_contact",
        lambda *_args, **_kwargs: pytest.fail("authority override reached resolution"),
    )
    ctx = SimpleNamespace(scope=SimpleNamespace(active_allowed=lambda _host: True))
    walk = fetch._walk(
        ctx, "https://example.test/", headers=headers,
        source_id="evidence.openapi",
    )
    with pytest.raises(ValueError, match="transport authority"):
        with walk:
            pytest.fail("authority-override request unexpectedly entered")
    with pytest.raises((TypeError, ValueError), match="transport authority|HTTP tokens"):
        fetch._preflight_managed_request(
            "https://example.test/", None, timeout=1, data=None,
            method="GET", headers=headers, max_redirects=0,
        )


def test_native_transport_refuses_request_for_a_different_approved_host(monkeypatch):
    monkeypatch.setattr(
        fetch, "_pinned_opener",
        lambda *_args, **_kwargs: pytest.fail("mismatched authority reached opener"),
    )
    contact = netguard.ContactState(
        "contact", [], [], answers=("8.8.8.8",), approved=("8.8.8.8",),
    )
    with pytest.raises(PermissionError, match="approved host"):
        fetch._open_contact(
            SimpleNamespace(run=None), "allowed.test", contact,
            fetch.urllib.request.Request("https://oos.test/"), 1.0,
            source_id="evidence.openapi",
        )


def test_native_contact_preclassifies_the_exact_url_port(monkeypatch):
    scope = _native_scope(block_private=False)
    repository = SimpleNamespace(_network_policy_scope=scope)
    ctx = SimpleNamespace(
        run=repository,
        profile=SimpleNamespace(block_private_targets=False),
    )
    monkeypatch.setattr(
        fetch, "_explicit_contact",
        lambda *_args, **_kwargs: netguard.ContactState(
            "contact", [], [], answers=("8.8.8.8",), approved=("8.8.8.8",),
        ),
    )
    observed = []
    monkeypatch.setattr(
        scope, "decide_peer",
        lambda peer, port, socket_type, protocol, **_kwargs: (
            observed.append((peer, port, socket_type, protocol))
            or SimpleNamespace(allowed=True)
        ),
    )
    result = fetch._contact(
        ctx, "example.test", port=8080, source_id="evidence.openapi",
    )
    assert result.approved == ("8.8.8.8",)
    assert observed == [(
        "8.8.8.8", 8080, socket.SOCK_STREAM, socket.IPPROTO_TCP,
    )]


@pytest.mark.parametrize("value", ["fe80::1%lo", "2001:db8::1%2"])
def test_textual_ipv6_zones_are_never_canonical_peer_authority(value):
    with pytest.raises(ValueError, match="invalid address"):
        netguard.canonical_ip_set((value,))
    assert _policy().host_allowed(value)[0] == "deny"
    with pytest.raises(network_dns.NetworkDNSRefused, match="name_invalid"):
        network_dns.resolve(_policy(), value)
    with pytest.raises(network_proxy.BrowserProxyRefused, match="authority_invalid"):
        network_proxy._authority(f"[{value}]:443", default_port=None, require_port=True)


@pytest.mark.parametrize("flow,scope", [(1, 0), (0, 1), (1, 2)])
def test_binary_ipv6_flow_and_scope_authority_is_refused(monkeypatch, flow, scope):
    raw = _sockaddr6("2001:db8::1", 443, flow=flow, scope=scope)
    monkeypatch.setattr(network_broker, "_read_process", lambda *_args: raw)
    with pytest.raises(NetworkBrokerRefused, match="ipv6_scope_refused"):
        network_broker._copy_destination(os.getpid(), 1, len(raw))


def test_sockaddr_shapes_are_exact_not_prefix_parsed(monkeypatch):
    raw4 = _sockaddr4("8.8.4.4", 443) + b"trailing"
    monkeypatch.setattr(network_broker, "_read_process", lambda *_args: raw4)
    with pytest.raises(NetworkBrokerRefused, match="sockaddr_length_invalid"):
        network_broker._copy_destination(os.getpid(), 1, len(raw4))
    raw6 = _sockaddr6("2001:4860:4860::8844", 443) + b"trailing"
    monkeypatch.setattr(network_broker, "_read_process", lambda *_args: raw6)
    with pytest.raises(NetworkBrokerRefused, match="sockaddr_length_invalid"):
        network_broker._copy_destination(os.getpid(), 1, len(raw6))


def test_all_zero_abstract_unix_name_is_not_collapsed_to_unnamed(monkeypatch):
    raw = struct.pack("=H", socket.AF_UNIX) + b"\x00" * 8
    monkeypatch.setattr(network_broker, "_read_process", lambda *_args: raw)
    destination = network_broker._copy_destination(os.getpid(), 1, len(raw))
    assert destination.unix_path == b"\x00" * 8
    assert _policy().decide_unix(destination.unix_path)[0] == "deny"


def test_netlink_destination_is_exact_and_never_generic_local_ipc(monkeypatch):
    raw = struct.pack("=HHII", socket.AF_NETLINK, 0, 7, 11)
    monkeypatch.setattr(network_broker, "_read_process", lambda *_args: raw)
    destination = network_broker._copy_destination(os.getpid(), 1, len(raw))
    assert (destination.netlink_pid, destination.netlink_groups) == (7, 11)
    monkeypatch.setattr(network_broker, "_read_process", lambda *_args: raw + b"x")
    with pytest.raises(NetworkBrokerRefused, match="sockaddr_length_invalid"):
        network_broker._copy_destination(os.getpid(), 1, len(raw) + 1)


def test_peer_decision_refreshes_new_interface_addresses(monkeypatch):
    monkeypatch.setattr(netguard, "own_ips", lambda: ("8.8.4.4",))
    decision, reason = _policy().decide(
        "8.8.4.4", 443, socket.SOCK_STREAM, socket.IPPROTO_TCP,
    )
    assert decision == "deny"
    assert "protected scanner" in reason


def test_interface_directed_broadcast_is_part_of_the_self_deny_snapshot():
    assert netguard._directed_broadcast("10.203.0.2", "255.255.255.0") == \
        "10.203.0.255"


def test_newly_observed_directed_broadcast_is_denied_even_for_private_targets(
        monkeypatch):
    monkeypatch.setattr(netguard, "own_ips", lambda: ("10.203.0.255",))
    policy = _policy(approved=("10.203.0.255",))
    decision, reason = policy.decide(
        "10.203.0.255", 53, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
    )
    assert decision == "deny"
    assert "protected scanner" in reason


@pytest.mark.parametrize("peer", [
    "0.0.0.1", "192.0.2.1", "240.0.0.1", "224.0.0.1", "2001:db8::1",
    "ff02::1",
])
def test_non_unicast_special_use_peers_are_unconditionally_denied(
        monkeypatch, peer):
    monkeypatch.setattr(netguard, "own_ips", lambda: ("10.203.0.2",))
    policy = _policy(approved=(peer,))
    decision, _reason = policy.decide(
        peer, 443, socket.SOCK_STREAM, socket.IPPROTO_TCP,
    )
    assert decision == "deny"


def test_google_ipv6_metadata_is_unconditionally_protected_and_subtracted(monkeypatch):
    peer = "fd20:ce::254"
    monkeypatch.setattr(netguard, "own_ips", lambda: ("10.203.0.2",))
    policy_value = _policy(approved=(peer,))
    decision, reason = policy_value.decide(
        peer, 80, socket.SOCK_STREAM, socket.IPPROTO_TCP,
    )
    assert decision == "deny" and "protected" in reason
    protected = netguard.protected_cidrs(
        own_ips=("10.203.0.2",), control_plane_cidrs=(), block_private=False,
    )
    assert "fd20:ce::254/128" in protected
    assert network_policy.subtract_protected_cidrs(
        ("fd20:ce::254/128",), protected,
    ) == ()


def test_blocking_connect_is_refused_without_mutating_the_shared_ofd():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.setblocking(False)
    target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    before = fcntl.fcntl(target.fileno(), fcntl.F_GETFL)
    fake = SimpleNamespace(
        _deadline=time.monotonic() + 1,
        _require_valid=lambda _identifier: None,
    )
    peer, port = listener.getsockname()
    destination = network_broker._Destination(
        socket.AF_INET, peer, port, _sockaddr4(peer, port),
    )
    result, error, selected = network_broker.NetworkBrokerSession._connect(
        fake, target.fileno(), destination,
        stop=threading.Event(), notification_id=1,
    )
    assert (result, error, selected) == (-1, errno.EOPNOTSUPP, None)
    assert fcntl.fcntl(target.fileno(), fcntl.F_GETFL) == before
    with pytest.raises(BlockingIOError):
        listener.accept()
    target.close()
    listener.close()


def test_nonblocking_connect_preserves_exact_flags_and_selected_peer():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target.setblocking(False)
    before = fcntl.fcntl(target.fileno(), fcntl.F_GETFL)
    fake = SimpleNamespace(
        _deadline=time.monotonic() + 1,
        _require_valid=lambda _identifier: None,
    )
    peer, port = listener.getsockname()
    destination = network_broker._Destination(
        socket.AF_INET, peer, port, _sockaddr4(peer, port),
    )
    result, error, selected = network_broker.NetworkBrokerSession._connect(
        fake, target.fileno(), destination,
        stop=threading.Event(), notification_id=1,
    )
    accepted, _address = listener.accept()
    assert (result, error, selected) == (0, 0, peer)
    assert fcntl.fcntl(target.fileno(), fcntl.F_GETFL) == before
    accepted.close()
    target.close()
    listener.close()


@pytest.mark.skipif(not hasattr(os, "pidfd_open"), reason="pidfd required")
def test_wrong_bootstrap_profile_kills_and_reaps_the_pinned_child():
    report_read, report_write = os.pipe2(os.O_CLOEXEC)
    child = os.fork()
    if child == 0:
        try:
            os.close(report_read)
            frame = network_broker._HANDOFF.pack(
                network_broker._HANDOFF_MAGIC,
                network_broker._HANDOFF_VERSION,
                network_broker._PROFILE_IDS["browser"],
                9,
            )
            os.write(report_write, frame)
            signal.pause()
        finally:
            os._exit(99)
    os.close(report_write)
    try:
        with pytest.raises(NetworkBrokerRefused, match="handoff_frame_invalid"):
            network_broker.duplicate_reported_listener(
                child, report_read, expected_profile="standard",
                deadline_monotonic=time.monotonic() + 1,
            )
        with pytest.raises(ChildProcessError):
            os.waitpid(child, os.WNOHANG)
    finally:
        os.close(report_read)


def test_listener_validation_rejects_an_arbitrary_cloexec_fd():
    fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    try:
        with pytest.raises(NetworkBrokerRefused, match="listener_fd_invalid"):
            network_broker._validate_listener_fd(fd)
    finally:
        os.close(fd)


def test_broker_plan_reserves_its_complete_terminal_footprint(monkeypatch):
    monkeypatch.setattr(network_broker, "_MAX_DECISIONS", 3)
    session = _recording_session()
    common = dict(
        syscall="connect", tid=10, peer="8.8.4.4", port=443,
        kind=socket.SOCK_STREAM, protocol=socket.IPPROTO_TCP,
        decision="allow", reason="fixture",
    )
    assert session._record(**common, stage="planned", result=None)
    assert session._record(**common, stage="admitted", result="peer-connected")
    assert session._record(**common, stage="settled", result="ok")
    assert len(session._records) == 3
    assert session._open_plans == {}
    assert session._dropped == 0
    assert session._stop.called == 0


def test_broker_refuses_n_plus_one_plan_before_an_effect(monkeypatch):
    monkeypatch.setattr(network_broker, "_MAX_DECISIONS", 5)
    session = _recording_session()
    common = dict(
        syscall="connect", peer="8.8.4.4", port=443,
        kind=socket.SOCK_STREAM, protocol=socket.IPPROTO_TCP,
        decision="allow", reason="fixture", stage="planned", result=None,
    )
    assert session._record(tid=10, **common)
    assert not session._record(tid=11, **common)
    assert len(session._records) == 1
    assert session._open_plans == {(10, "connect"): 2}
    assert session._fatal == "network_broker_decision_record_overflow"
    assert session._dropped == 1
    assert session._stop.called == 1


def test_concurrent_plan_reservations_cannot_overbook_terminal_rows(monkeypatch):
    monkeypatch.setattr(network_broker, "_MAX_DECISIONS", 6)
    session = _recording_session()
    barrier = threading.Barrier(4)
    outcomes = []

    def reserve(tid):
        barrier.wait()
        outcomes.append(session._record(
            syscall="sendto", tid=tid, peer="8.8.4.4", port=53,
            kind=socket.SOCK_DGRAM, protocol=socket.IPPROTO_UDP,
            decision="allow", reason="fixture", stage="planned", result=None,
        ))

    threads = [threading.Thread(target=reserve, args=(tid,)) for tid in (1, 2, 3)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(1)
    assert outcomes.count(True) == 2
    assert outcomes.count(False) == 1
    assert len(session._records) + sum(session._open_plans.values()) == 6
    assert session._fatal == "network_broker_decision_record_overflow"


def test_aborted_notification_consumes_its_reserved_terminal_row():
    session = _recording_session()
    session._architecture = SimpleNamespace(
        connect=42, sendto=44, sendmsg=46, bind=49, listen=50,
        accept=43, accept4=288,
    )
    common = dict(
        syscall="connect", tid=10, peer="8.8.4.4", port=443,
        kind=socket.SOCK_STREAM, protocol=socket.IPPROTO_TCP,
        decision="allow", reason="fixture",
    )
    assert session._record(**common, stage="planned", result=None)
    notification = network_broker._SeccompNotif()
    notification.pid = 10
    notification.data.nr = 42
    session._settle_abandoned_notification(notification, "operation-aborted")
    assert session._open_plans == {}
    assert [record.stage for record in session._records] == ["planned", "settled"]
    assert session._records[-1].result == "operation-aborted"


@pytest.mark.parametrize("token", [
    "content-length", "host", "transfer-encoding", "proxy-authorization",
])
def test_proxy_connection_tokens_cannot_reframe_a_forwarded_body(token):
    request = (
        b"POST http://example.test/upload HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Content-Length: 4\r\n"
        + f"Connection: {token}\r\n".encode("ascii")
        + b"\r\ntest"
    )
    head, remainder = request.split(b"\r\n\r\n", 1)
    with pytest.raises(network_proxy.BrowserProxyRefused,
                       match="connection_token_refused"):
        network_proxy._parse_request(head + b"\r\n\r\n", remainder)


def test_proxy_refusal_response_cannot_block_or_begin_after_cancellation(monkeypatch):
    fence = NetworkEffectFence()
    proxy = network_proxy.PinnedBrowserProxy(
        _policy(), network_broker.ControlEndpointRegistry(),
        deadline_monotonic=time.monotonic() + 2.0, effect_fence=fence,
    )
    proxy._registration = object()
    monkeypatch.setattr(
        proxy._registry, "consume_connection", lambda *_args, **_kwargs: None,
    )

    witness, client_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    payload = b"x" * 65536
    while True:
        try:
            os.write(client_fd, payload)
        except BlockingIOError:
            break

    send_entered = threading.Event()

    class SaturatedClient:
        def fileno(self):
            return client_fd

        def setblocking(self, enabled):
            return os.set_blocking(client_fd, enabled)

        def send(self, body):
            send_entered.set()
            return os.write(client_fd, body)

        def sendall(self, _body):
            pytest.fail("proxy refusal bypassed its bounded fenced send")

    client = SaturatedClient()
    monkeypatch.setattr(proxy, "_close_tracked", lambda _handle: os.close(client_fd))
    assert proxy._slots.acquire(blocking=False)
    select_entered = threading.Event()
    real_select = network_proxy.select.select

    def observed_select(*args, **kwargs):
        select_entered.set()
        return real_select(*args, **kwargs)

    monkeypatch.setattr(network_proxy.select, "select", observed_select)
    worker = threading.Thread(target=proxy._serve_thread, args=(client,))
    worker.start()
    assert select_entered.wait(1.0)
    fence.cancel()
    worker.join(1.0)
    assert not worker.is_alive()
    assert not send_entered.is_set()
    os.close(witness)


def test_proxy_listener_registration_is_owned_before_cancel_can_return(monkeypatch):
    fence = NetworkEffectFence()
    registry = network_broker.ControlEndpointRegistry()
    proxy = network_proxy.PinnedBrowserProxy(
        _control_policy(browser=True), registry,
        deadline_monotonic=time.monotonic() + 5.0, effect_fence=fence,
    )
    registered = threading.Event()
    release = threading.Event()
    control = []
    real_register = registry.register_worker_listener

    def blocked_register(**kwargs):
        value = real_register(**kwargs)
        control.append(value)
        registered.set()
        assert release.wait(2.0)
        return value

    monkeypatch.setattr(registry, "register_worker_listener", blocked_register)
    start_faults = []
    starter = threading.Thread(
        target=lambda: _capture_fault(proxy.start, start_faults),
    )
    starter.start()
    assert registered.wait(1.0)
    cancelled = threading.Event()

    def cancel():
        fence.cancel()
        cancelled.set()

    canceller = threading.Thread(target=cancel)
    canceller.start()
    assert fence.event.wait(1.0)
    assert not cancelled.wait(0.05)
    release.set()
    starter.join(2.0)
    canceller.join(2.0)
    assert not starter.is_alive() and not canceller.is_alive()
    assert start_faults
    assert cancelled.is_set()
    assert registry.worker_listener_closed(control[0])
    assert proxy._listener is None
    assert proxy._registration is None
    assert proxy._accept_thread is None


def test_proxy_listener_close_fault_retains_retry_authority(monkeypatch):
    class FirstCloseFails(socket.socket):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.close_calls = 0

        def close(self):
            self.close_calls += 1
            if self.close_calls == 1:
                raise OSError(errno.EIO, "injected listener close fault")
            return super().close()

    facade = SimpleNamespace(
        socket=lambda *args, **kwargs: FirstCloseFails(*args, **kwargs),
        AF_INET=socket.AF_INET, SOCK_STREAM=socket.SOCK_STREAM,
        IPPROTO_TCP=socket.IPPROTO_TCP, SOL_SOCKET=socket.SOL_SOCKET,
        SO_REUSEADDR=socket.SO_REUSEADDR,
    )
    monkeypatch.setattr(network_proxy, "socket", facade)
    fence = NetworkEffectFence()
    proxy = network_proxy.PinnedBrowserProxy(
        _control_policy(browser=True), network_broker.ControlEndpointRegistry(),
        deadline_monotonic=time.monotonic() + 5.0, effect_fence=fence,
    )
    proxy.start()
    listener = proxy._listener
    proxy.stop()
    assert listener.fileno() >= 0
    assert proxy._listener is listener
    assert not proxy.summary()["complete"]
    proxy.stop()
    assert listener.fileno() == -1
    assert proxy._listener is None


def test_proxy_accept_and_track_are_one_cancellation_epoch(monkeypatch):
    fence = NetworkEffectFence()
    proxy = network_proxy.PinnedBrowserProxy(
        _control_policy(browser=True), network_broker.ControlEndpointRegistry(),
        deadline_monotonic=time.monotonic() + 5.0, effect_fence=fence,
    )
    accepted_socket, client = socket.socketpair()

    class Listener:
        def accept(self):
            return accepted_socket, ("127.0.0.1", 1)

    listener = Listener()
    proxy._listener = listener
    monkeypatch.setattr(
        network_proxy.select, "select",
        lambda *_args, **_kwargs: ((listener,), (), ()),
    )
    real_track = fence.track_socket
    entered = threading.Event()
    release = threading.Event()
    accepted = []

    def blocked_track(handle):
        if handle is not proxy._listener:
            accepted.append(handle)
            entered.set()
            assert release.wait(2.0)
        return real_track(handle)

    fence.track_socket = blocked_track
    worker = threading.Thread(target=proxy._accept)
    worker.start()
    assert entered.wait(1.0)
    cancelled = threading.Event()

    def cancel():
        fence.cancel()
        cancelled.set()

    canceller = threading.Thread(target=cancel)
    canceller.start()
    assert fence.event.wait(1.0)
    assert not cancelled.wait(0.05)
    release.set()
    canceller.join(2.0)
    assert not canceller.is_alive()
    assert cancelled.is_set()
    worker.join(2.0)
    assert not worker.is_alive()
    assert accepted and accepted[0].fileno() == -1
    proxy._listener = None
    client.close()


def test_cdp_listener_registration_is_owned_before_cancel_can_return(monkeypatch):
    fence = NetworkEffectFence()
    registry = network_broker.ControlEndpointRegistry()
    bridge, pipe_fds = _cdp_fixture(fence=fence, registry=registry)
    try:
        registered = threading.Event()
        release = threading.Event()
        control = []
        real_register = registry.register_worker_listener

        def blocked_register(**kwargs):
            value = real_register(**kwargs)
            control.append(value)
            registered.set()
            assert release.wait(2.0)
            return value

        monkeypatch.setattr(
            registry, "register_worker_listener", blocked_register,
        )
        start_faults = []
        starter = threading.Thread(
            target=lambda: _capture_fault(bridge.start, start_faults),
        )
        starter.start()
        assert registered.wait(1.0)
        cancelled = threading.Event()

        def cancel():
            fence.cancel()
            cancelled.set()

        canceller = threading.Thread(target=cancel)
        canceller.start()
        assert fence.event.wait(1.0)
        assert not cancelled.wait(0.05)
        release.set()
        starter.join(2.0)
        canceller.join(2.0)
        assert not starter.is_alive() and not canceller.is_alive()
        assert start_faults
        assert cancelled.is_set()
        assert registry.worker_listener_closed(control[0])
        assert bridge._listener is None
        assert bridge._registration is None
        assert bridge._thread is None
        assert bridge._chrome_output == bridge._chrome_input == -1
    finally:
        for fd in pipe_fds:
            os.close(fd)


def test_cdp_listener_close_fault_retains_retry_authority(monkeypatch):
    class FirstCloseFails(socket.socket):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.close_calls = 0

        def close(self):
            self.close_calls += 1
            if self.close_calls == 1:
                raise OSError(errno.EIO, "injected listener close fault")
            return super().close()

    facade = SimpleNamespace(
        socket=lambda *args, **kwargs: FirstCloseFails(*args, **kwargs),
        AF_INET=socket.AF_INET, SOCK_STREAM=socket.SOCK_STREAM,
        IPPROTO_TCP=socket.IPPROTO_TCP, SOL_SOCKET=socket.SOL_SOCKET,
        SO_REUSEADDR=socket.SO_REUSEADDR,
    )
    monkeypatch.setattr(network_cdp, "socket", facade)
    fence = NetworkEffectFence()
    bridge, pipe_fds = _cdp_fixture(
        fence=fence, registry=network_broker.ControlEndpointRegistry(),
    )
    try:
        bridge.start()
        listener = bridge._listener
        bridge.stop()
        assert listener.fileno() >= 0
        assert bridge._listener is listener
        assert not bridge.summary()["complete"]
        bridge.stop()
        assert listener.fileno() == -1
        assert bridge._listener is None
    finally:
        for fd in pipe_fds:
            os.close(fd)


def test_cdp_accept_and_track_are_one_cancellation_epoch(monkeypatch):
    fence = NetworkEffectFence()
    bridge, pipe_fds = _cdp_fixture(
        fence=fence, registry=network_broker.ControlEndpointRegistry(),
    )
    client = None
    try:
        accepted_socket, client = socket.socketpair()

        class Listener:
            def accept(self):
                return accepted_socket, ("127.0.0.1", 1)

        listener = Listener()
        bridge._listener = listener
        bridge._registration = object()
        monkeypatch.setattr(
            network_cdp.select, "select",
            lambda *_args, **_kwargs: ((listener,), (), ()),
        )
        real_track = fence.track_socket
        entered = threading.Event()
        release = threading.Event()
        accepted = []

        def blocked_track(handle):
            if handle is not bridge._listener:
                accepted.append(handle)
                entered.set()
                assert release.wait(2.0)
            return real_track(handle)

        fence.track_socket = blocked_track
        worker = threading.Thread(target=bridge._run)
        worker.start()
        assert entered.wait(1.0)
        cancelled = threading.Event()

        def cancel():
            fence.cancel()
            cancelled.set()

        canceller = threading.Thread(target=cancel)
        canceller.start()
        assert fence.event.wait(1.0)
        assert not cancelled.wait(0.05)
        release.set()
        canceller.join(2.0)
        assert not canceller.is_alive()
        assert cancelled.is_set()
        worker.join(2.0)
        assert not worker.is_alive()
        bridge._listener = None
        bridge._registration = None
        bridge.stop()
        assert accepted and accepted[0].fileno() == -1
    finally:
        if client is not None:
            client.close()
        for fd in pipe_fds:
            os.close(fd)


@pytest.mark.parametrize("cleanup_path", ("discard", "revoke", "consume"))
def test_control_grant_close_fault_retains_exact_retry_authority(
        monkeypatch, cleanup_path):
    registry = network_broker.ControlEndpointRegistry()
    client, accepted = socket.socketpair()
    held = os.dup(client.fileno())
    listener_identity = (123, 456)
    request_id = "a" * 32
    listener_owner = object()
    grant_owner = object()
    client_endpoint = ("127.0.0.1", 40000)
    server_endpoint = ("127.0.0.1", 50000)
    monkeypatch.setattr(
        network_broker, "_socket_metadata",
        lambda _fd: (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP),
    )

    def connection_endpoints(fd, _family):
        if fd == accepted.fileno():
            return server_endpoint, client_endpoint
        return client_endpoint, server_endpoint

    monkeypatch.setattr(registry, "_connection_endpoints", connection_endpoints)
    control = network_broker._ControlListener(
        -1, "", 0, listener_identity, request_id, os.getpid(), -1,
        listener_owner, (), (), "pinned-browser-proxy",
    )
    grant = network_broker._ControlGrant(
        listener_identity, listener_owner, request_id, grant_owner,
        held, network_broker._socket_identity(client.fileno()), os.getpid(),
        ("b" * 64, 1), socket.AF_INET, client_endpoint, server_endpoint,
        committed=True,
    )
    registry._grants.append(grant)
    real_close = network_broker.os.close
    injected = []

    def close_once(fd):
        if fd == held and not injected:
            injected.append(fd)
            raise OSError(errno.EIO, "injected grant close fault")
        return real_close(fd)

    monkeypatch.setattr(network_broker.os, "close", close_once)

    def cleanup():
        if cleanup_path == "discard":
            return registry.discard_owner(grant_owner)
        if cleanup_path == "revoke":
            return registry.revoke_connection(grant)
        return registry.consume_connection(
            control, accepted_fd=accepted.fileno(),
            deadline_monotonic=time.monotonic() + 1.0,
            stop_event=threading.Event(),
        )

    try:
        with pytest.raises(
                NetworkBrokerRefused,
                match="network_broker_control_grant_close_failed"):
            cleanup()
        assert registry._grants == [grant]
        observed = os.fstat(held)
        assert (observed.st_dev, observed.st_ino) == grant.client_identity

        result = cleanup()
        if cleanup_path == "consume":
            assert result is grant
        assert registry._grants == []
        with pytest.raises(OSError) as closed:
            os.fstat(held)
        assert closed.value.errno == errno.EBADF
        assert injected == [held]
    finally:
        try:
            real_close(held)
        except OSError:
            pass
        client.close()
        accepted.close()


def test_proxy_final_peer_refusal_never_falls_through_to_a_second_answer(monkeypatch):
    decisions = iter((
        ("allow", "initial peer one"),
        ("allow", "initial peer two"),
        ("deny", "peer one became protected"),
    ))
    policy_witness = SimpleNamespace(
        host_allowed=lambda _host: ("allow", "host admitted"),
        decide_resolved=lambda *_args: next(decisions),
    )
    proxy = network_proxy.PinnedBrowserProxy.__new__(
        network_proxy.PinnedBrowserProxy,
    )
    proxy._policy = policy_witness
    proxy._deadline = time.monotonic() + 1.0
    proxy._stop = threading.Event()
    proxy._effect_fence = NetworkEffectFence()
    proxy._record = lambda **_row: True
    proxy._track = lambda _handle: None
    proxy._close_tracked = lambda handle: handle.close()
    monkeypatch.setattr(
        network_dns, "resolve",
        lambda *_args, **_kwargs: (("8.8.8.8", "8.8.4.4"), "ok"),
    )
    attempted = []

    class ConnectedSocket:
        def __init__(self, *_args):
            self.endpoint = None

        def setblocking(self, _enabled):
            return None

        def connect_ex(self, endpoint):
            self.endpoint = endpoint
            attempted.append(endpoint[0])
            return 0

        def getpeername(self):
            return self.endpoint

        def close(self):
            return None

    monkeypatch.setattr(network_proxy.socket, "socket", ConnectedSocket)
    with pytest.raises(network_proxy.BrowserProxyRefused,
                       match="selected_peer_refused"):
        proxy._dial("CONNECT", "example.test", 443)
    assert attempted == ["8.8.8.8"]


def test_proxy_plan_reserves_its_terminal_record_before_contact(monkeypatch):
    monkeypatch.setattr(network_proxy, "_MAX_PROXY_RECORDS", 2)
    proxy = network_proxy.PinnedBrowserProxy.__new__(
        network_proxy.PinnedBrowserProxy,
    )
    proxy._lock = threading.Lock()
    proxy._records = []
    proxy._open_plans = {}
    proxy._dropped = 0
    proxy._fatal = None
    proxy._stop = _StopWitness()
    common = dict(
        method="CONNECT", host="example.test", port=443,
        peer="8.8.4.4", decision="allow", reason="fixture",
    )
    assert proxy._record(stage="peer-planned", **common)
    assert not proxy._record(
        stage="authority", method="CONNECT", host="example.test",
        port=443, decision="allow", reason="fixture",
    )
    assert proxy._record(
        stage="peer-settled", **{**common, "decision": "deny"},
    )
    assert proxy._open_plans == {}
    assert [record.stage for record in proxy._records] == [
        "peer-planned", "peer-settled",
    ]
    assert proxy._fatal == "network_proxy_record_overflow"


def _recording_cdp_bridge():
    bridge = network_cdp.PinnedCDPBridge.__new__(network_cdp.PinnedCDPBridge)
    bridge._method_counts = {}
    return bridge


def test_cdp_connection_plan_reserves_terminal_truth(monkeypatch):
    monkeypatch.setattr(network_cdp, "_MAX_CDP_RECORDS", 2)
    bridge = _recording_cdp_bridge()
    bridge._lock = threading.Lock()
    bridge._records = []
    bridge._terminal_reservations = 0
    bridge._dropped = 0
    bridge._fatal = None
    bridge._stop = _StopWitness()
    assert bridge._record(
        "connection-planned", "allow", "fixture", connection=1,
    )
    assert not bridge._record("websocket", "allow", "fixture", connection=1)
    assert bridge._record(
        "connection-settled", "deny", "fixture fault", connection=1,
    )
    assert bridge._terminal_reservations == 0
    assert [record.stage for record in bridge._records] == [
        "connection-planned", "connection-settled",
    ]
    assert bridge._fatal == "network_cdp_record_overflow"


@pytest.mark.parametrize("method", [
    "Security.setIgnoreCertificateErrors",
    "Security.setOverrideCertificateErrors",
    "Security.handleCertificateError",
])
def test_cdp_certificate_bypass_methods_are_refused(method):
    bridge = _recording_cdp_bridge()
    with pytest.raises(network_cdp.CDPBridgeRefused,
                       match="certificate_bypass_refused"):
        bridge._admit_client_document({"id": 1, "method": method, "params": {}})
    assert bridge._method_counts == {}


@pytest.mark.parametrize("payload", [
    b'{"id":1,"method":"Runtime.enable","method":"Security.setIgnoreCertificateErrors"}',
    b'{"id":1,"method":"Runtime.enable","params":{"value":NaN}}',
    b'{"id":1,"method":"Runtime.enable","params":{"value":Infinity}}',
    b'{"id":1,"method":"Runtime.enable","params":{"value":-Infinity}}',
])
def test_cdp_json_rejects_duplicate_keys_and_nonfinite_numbers(payload):
    with pytest.raises(network_cdp.CDPBridgeRefused,
                       match="network_cdp_message_invalid"):
        network_cdp.PinnedCDPBridge._document(payload)


@pytest.mark.parametrize("method,params", [
    (
        "Target.sendMessageToTarget",
        {
            "sessionId": "fixture",
            "message": json.dumps({
                "id": 2,
                "method": "Security.setIgnoreCertificateErrors",
                "params": {"ignore": True},
            }),
        },
    ),
    (
        "Target.sendMessageToTarget",
        {
            "sessionId": "fixture",
            "message": json.dumps({
                "id": 2,
                "method": "Fetch.continueRequest",
                "params": {
                    "url": "https://oos.test/",
                    "headers": [{"name": "Host", "value": "oos.test"}],
                },
            }),
        },
    ),
    ("Target.exposeDevToolsProtocol", {"targetId": "fixture"}),
    (
        "Target.createBrowserContext",
        {"proxyServer": "http://oos.test:8080", "proxyBypassList": "*"},
    ),
])
def test_cdp_refuses_nested_or_delegated_network_authority(method, params):
    bridge = _recording_cdp_bridge()
    with pytest.raises(network_cdp.CDPBridgeRefused,
                       match="encapsulated_authority_refused"):
        bridge._admit_client_document({
            "id": 1, "method": method, "params": params,
        })
    assert bridge._method_counts == {}


@pytest.mark.parametrize("method", [
    "Fetch.continueRequest",
    "Network.continueInterceptedRequest",
])
def test_cdp_interception_cannot_override_the_admitted_url(method):
    bridge = _recording_cdp_bridge()
    with pytest.raises(network_cdp.CDPBridgeRefused,
                       match="url_override_refused"):
        bridge._admit_client_document({
            "id": 1,
            "method": method,
            "params": {"requestId": "fixture", "url": "https://oos.test/"},
        })
    assert bridge._method_counts == {}


@pytest.mark.parametrize("method,headers", [
    ("Fetch.continueRequest", [{"name": "Host", "value": "oos.test"}]),
    ("Network.continueInterceptedRequest", {":authority": "oos.test"}),
    ("Network.setExtraHTTPHeaders", {"hOsT": "oos.test"}),
])
def test_cdp_controller_cannot_override_http_authority(method, headers):
    bridge = _recording_cdp_bridge()
    with pytest.raises(network_cdp.CDPBridgeRefused,
                       match="authority_header_refused"):
        bridge._admit_client_document({
            "id": 1, "method": method, "params": {"headers": headers},
        })
    assert bridge._method_counts == {}


def test_cdp_resume_without_authority_override_remains_compatible():
    bridge = _recording_cdp_bridge()
    bridge._admit_client_document({
        "id": 1,
        "method": "Fetch.continueRequest",
        "params": {
            "requestId": "fixture",
            "headers": [{"name": "Accept", "value": "*/*"}],
        },
    })
    assert bridge._method_counts == {"Fetch.continueRequest": 1}
