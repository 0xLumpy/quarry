from __future__ import annotations

import json
import stat
import urllib.request
from types import SimpleNamespace

import pytest

from quarry_recon import fetch, network_dns, network_policy, osint


pytestmark = pytest.mark.offline


def _profile():
    return SimpleNamespace(
        target="example.test", apex_domains=["example.test"], cidr=[], oos=[],
        block_private_targets=False, http_rl=0,
    )


def _bound_session(tmp_path):
    session = osint.OsintSession(tmp_path, "example.test", ts="native-provider")
    profile = _profile()
    ctx = osint._OsintHttpRepository(
        session, profile, SimpleNamespace(active_allowed=lambda _host: False),
    )
    policy = network_policy.NetworkPolicyScope(
        block_private_targets=False, apex_domains=("example.test",),
        own_ips=("192.0.2.10",), resolver_ips=("1.1.1.1",),
    )
    policy.bind(ctx)
    session._http_context = ctx
    return session, ctx


def test_osint_provider_refuses_unbound_session_without_ambient_transport(monkeypatch, tmp_path):
    session = osint.OsintSession(tmp_path, "example.test", ts="unbound-provider")
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *_a, **_k: pytest.fail("ambient urlopen reached"))
    monkeypatch.setattr(fetch, "_open_contact", lambda *_a, **_k: pytest.fail("ambient path reached"))

    osint._azmap(session, "example.test", lambda _line: None, 1)

    assert session._lane_failures[0]["tool"] == "azmap"
    assert "bound NetworkPolicyScope" in session._lane_failures[0]["why"]


def test_osint_provider_refuses_mixed_public_private_answer_before_contact(monkeypatch, tmp_path):
    session, ctx = _bound_session(tmp_path)
    monkeypatch.setattr(network_dns, "resolve", lambda *_a, **_k: (("8.8.8.8", "10.0.0.2"), "ok"))
    monkeypatch.setattr(fetch, "_open_contact", lambda *_a, **_k: pytest.fail("rebound peer contacted"))

    with pytest.raises(RuntimeError, match="refused by the run network scope"):
        osint._provider_get(session, "https://azmap.dev/api/tenant?domain=example.test",
                            source_id="osint.azmap", timeout=1)

    rows = [json.loads(line) for line in (session.raw / "network" / "policy.jsonl").read_text().splitlines()]
    assert rows[0]["record_type"] == "scope"
    assert network_policy.scope_for(ctx) is not None


def test_osint_native_provider_helpers_use_exact_registered_source_ids(monkeypatch, tmp_path):
    session, ctx = _bound_session(tmp_path)
    seen = []

    def provider(_ctx, _url, *, source_id, **_kwargs):
        seen.append(source_id)
        return b'{"data": {}}' if source_id == "osint.asrank" else b"{}", _url, 200

    monkeypatch.setattr(fetch, "scoped_public_provider_get", provider)
    osint._provider_get(session, "https://azmap.dev/api/tenant?domain=example.test",
                        source_id="osint.azmap", timeout=1)
    osint._provider_post_json(session, "https://api.asrank.caida.org/v2/graphql", {"query": "{}"},
                              source_id="osint.asrank", timeout=1)
    osint._whoxy_get("https://api.whoxy.com/?key=secret&account=balance", 1, ctx=ctx)
    osint._provider_get(session, "https://rdap.org/ip/8.8.8.8", source_id="osint.rdap", timeout=1)

    assert seen == ["osint.azmap", "osint.asrank", "osint.whoxy", "osint.rdap"]


def test_osint_whoxy_errors_drop_query_secrets_and_policy_trace_is_private(monkeypatch, tmp_path):
    session, ctx = _bound_session(tmp_path)
    secret = "WHOXY-DO-NOT-RETAIN"
    monkeypatch.setattr(fetch, "scoped_public_provider_get",
                        lambda *_a, **_k: (b'{"status":0}', "https://api.whoxy.com/", 401))

    raw, error = osint._whoxy_get(
        f"https://api.whoxy.com/?key={secret}&account=balance", 1, ctx=ctx,
    )

    assert raw == b'{"status":0}'
    assert error.filename == "https://api.whoxy.com/"
    assert secret not in repr(error)
    trace = session.raw / "network" / "policy.jsonl"
    assert stat.S_IMODE(trace.stat().st_mode) == 0o600
