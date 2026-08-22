from __future__ import annotations

import json
import socket
from types import SimpleNamespace

import pytest

from quarry_recon import fetch, network_dns, network_policy, osint
from quarry_recon.phases import vertical
from quarry_recon.store import Run


pytestmark = pytest.mark.offline


def _bound_scope(repository, *, apex="example.test"):
    scope = network_policy.NetworkPolicyScope(
        block_private_targets=False, apex_domains=(apex,), own_ips=("192.0.2.10",),
        resolver_ips=("1.1.1.1",),
    )
    scope.bind(repository)
    return scope


def _resolver(answers):
    def resolve(policy, host, *, on_event, **_kwargs):
        assert policy.resolver_ips == ("1.1.1.1",)
        on_event("dns-planned", "1.1.1.1", 53, "allow", "DNS exchange planned")
        on_event("dns-settled", "1.1.1.1", 53, "allow", "DNS exchange settled")
        return answers, "ok"
    return resolve


def _trace_rows(root):
    return [json.loads(line) for line in (root / "raw" / "network" / "policy.jsonl")
            .read_text().splitlines()]


def test_rdap_address_resolution_is_bound_traced_and_never_uses_getaddrinfo(monkeypatch, tmp_path):
    session = osint.OsintSession(tmp_path, "example.test", ts="rdap-dns")
    profile = SimpleNamespace(apex_domains=["example.test"], block_private_targets=False)
    context = osint._OsintHttpRepository(
        session, profile, SimpleNamespace(active_allowed=lambda _host: False),
    )
    _bound_scope(session)
    context._network_policy_scope = network_policy.scope_for(session)
    session._http_context = context
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *_a, **_k: pytest.fail("ambient getaddrinfo reached"))
    monkeypatch.setattr(network_dns, "resolve", _resolver(("8.8.8.8", "2606:4700::1111")))

    assert osint._rdap_addresses(profile, session) == {
        "example.test": ["2606:4700::1111", "8.8.8.8"],
    }
    rows = _trace_rows(session.dir)
    rows = [row for row in rows if row["source_id"] == "osint.rdap_resolve"]
    assert [row["record_type"] for row in rows] == ["planned", "settlement"]
    assert rows[0]["request_id"] == rows[1]["request_id"]
    assert rows[0]["destination"]["host"] == "example.test"


def test_rdap_resolution_fault_is_a_gap_without_ambient_dns(monkeypatch, tmp_path):
    session = osint.OsintSession(tmp_path, "example.test", ts="rdap-dns-fault")
    profile = SimpleNamespace(apex_domains=["example.test"], block_private_targets=False)
    _bound_scope(session)
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *_a, **_k: pytest.fail("ambient getaddrinfo reached"))
    monkeypatch.setattr(network_dns, "resolve",
                        lambda *_a, **_k: (_ for _ in ()).throw(
                            network_dns.NetworkDNSRefused("resolver fault"),
                        ))

    assert osint._rdap_addresses(profile, session) == {"example.test": []}
    assert any("bound DNS resolution failed" in row["why"] for row in session._lane_failures)


def test_rdap_uses_only_resolver_contact_approved_answers(monkeypatch, tmp_path):
    session = osint.OsintSession(tmp_path, "example.test", ts="rdap-dns-denied")
    profile = SimpleNamespace(apex_domains=["example.test"], block_private_targets=False)
    context = osint._OsintHttpRepository(
        session, profile, SimpleNamespace(active_allowed=lambda _host: False),
    )
    _bound_scope(session)
    context._network_policy_scope = network_policy.scope_for(session)
    session._http_context = context
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *_a, **_k: pytest.fail("ambient getaddrinfo reached"))
    monkeypatch.setattr(network_dns, "resolve", _resolver(("192.0.2.10",)))

    assert osint._rdap_addresses(profile, session) == {"example.test": []}
    assert any("resolved to no address" in row["why"] for row in session._lane_failures)


def test_rdap_provider_and_target_resolver_authorities_are_distinct():
    scope = network_policy.NetworkPolicyScope(
        block_private_targets=False, apex_domains=("example.test",), own_ips=("192.0.2.10",),
        resolver_ips=("1.1.1.1",),
    )
    assert scope.host_allowed("example.test", source_id="osint.rdap")[0] == "deny"
    assert scope.host_allowed("example.test", source_id="osint.rdap_resolve")[0] == "allow"


def test_wildcard_guard_uses_bound_dns_and_keeps_its_source_trace(monkeypatch, tmp_path):
    run = Run.create(tmp_path, "example.test")
    _bound_scope(run)
    context = SimpleNamespace(
        run=run, profile=SimpleNamespace(block_private_targets=False, http_rl=0),
        scope=SimpleNamespace(passive_only=False), echo=lambda _line: None,
    )
    monkeypatch.setattr(vertical, "have", lambda tool: tool == "httpx")
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *_a, **_k: pytest.fail("ambient getaddrinfo reached"))
    monkeypatch.setattr(network_dns, "resolve", _resolver(("192.0.2.10",)))

    class SweepResult:
        eligible_pairs = attempted_pairs = targets_admitted = targets_complete = 0
        targets_remaining = deferred_targets = targets_refused = 0
        stop = stop_kind = ""
        machinery = []
        contained = []
        remainder_known = False

        @staticmethod
        def pair_remainder():
            return {"refused": 0, "unselectable": 0, "deferred": 0, "stopped": 0,
                    "bound": 0, "total": 0}

    def sweep(**kwargs):
        assert kwargs["admit"]("example.test") is False
        return SweepResult()

    monkeypatch.setattr(vertical.sweep, "run_sweep", sweep)
    stats = {"blocked": {"self_or_private": 0, "zone_cap": 0}}
    vertical._wc_differentiate(
        context, ["example.test"], words=["api"], phase="vertical", label="wildcard",
        source="wildcard-http", st=stats, source_id="vertical.wildcard_http",
        kept=set(), novel=set(), word_spend=1,
    )

    assert stats["blocked"]["self_or_private"] == 1
    rows = [row for row in _trace_rows(run.dir) if row["source_id"] == "vertical.wildcard_guard"]
    assert [row["record_type"] for row in rows] == ["planned", "settlement", "planned", "settlement"]
    assert rows[0]["request_id"] == rows[1]["request_id"]
    assert rows[2]["request_id"] == rows[3]["request_id"]
