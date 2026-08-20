from __future__ import annotations

from types import SimpleNamespace
import urllib.request

import pytest

from quarry_recon import fetch, netguard, network_dns, network_policy
from quarry_recon.phases import probe, vertical


pytestmark = pytest.mark.offline


def _scope_context(monkeypatch):
    scope = network_policy.NetworkPolicyScope(
        block_private_targets=False,
        requested_cidrs=("10.0.0.0/24",), apex_domains=("example.test",),
        own_ips=("192.0.2.10",), resolver_ips=("1.1.1.1",),
    )
    # This unit test exercises the transport decision before a real Run owns
    # its trace file; trace persistence is covered by the network-boundary suite.
    monkeypatch.setattr(scope, "_trace", lambda _document: None)
    return SimpleNamespace(
        run=SimpleNamespace(_network_policy_scope=scope),
        profile=SimpleNamespace(block_private_targets=False, http_rl=0),
        scope=SimpleNamespace(active_allowed=lambda _host: False),
    )


def test_native_public_providers_have_no_unbound_or_rebound_http_path(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        urllib.request, "urlopen",
        lambda *_args, **_kwargs: calls.append(True) or pytest.fail("ambient urlopen reached"),
    )

    # Every in-process provider adapter refuses before any network effect when
    # the Run did not bind a NetworkPolicyScope.
    with pytest.raises(PermissionError):
        probe._shodan_get(None, "https://api.shodan.io/api-info?key=canary",
                          source_id="probe.shodan_host", timeout=1, max_body=16)
    for source_id, url in (
        ("vertical.censys", "https://api.platform.censys.io/v3/global/search/query"),
        ("vertical.certspotter", "https://api.certspotter.com/v1/issuances?domain=example.test"),
        ("vertical.crtsh", "https://crt.sh/?q=%25.example.test&output=json"),
        ("vertical.shosubgo", "https://api.shodan.io/dns/domain/example.test?key=canary"),
    ):
        with pytest.raises(PermissionError):
            vertical._provider_get(None, url, source_id=source_id, timeout=1, max_body=16)
    _rows, _total, error = probe._shodan_page(
        "canary", "http.favicon.hash", "1", 1, sink=tmp_path / "page.json", ctx=None,
    )
    assert isinstance(error, PermissionError)
    assert not calls

    # A rebinding/mixed answer is refused as a whole public-provider answer
    # set.  In particular, the safe address must not be tried after a private
    # peer appears in the mediated DNS reply.
    ctx = _scope_context(monkeypatch)
    monkeypatch.setattr(netguard, "own_ips", lambda: ("192.0.2.10",))
    monkeypatch.setattr(netguard, "interface_snapshot",
                        lambda: netguard.InterfaceSnapshot(("192.0.2.10",), ("255.255.255.255",)))
    monkeypatch.setattr(network_dns, "resolve",
                        lambda *_args, **_kwargs: (("8.8.8.8", "10.0.0.2"), "ok"))
    monkeypatch.setattr(netguard, "record_internal", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(fetch, "_open_contact",
                        lambda *_args, **_kwargs: pytest.fail("a rebound provider peer was contacted"))
    body, final, status = fetch.scoped_public_provider_get(
        ctx, "https://api.shodan.io/api-info?key=canary", source_id="probe.shodan_host",
        timeout=1, max_body=16,
    )
    assert (body, final, status) == (None, "https://api.shodan.io/api-info?key=canary", 0)
    assert not calls


def test_paid_shodan_error_does_not_retain_the_api_key(monkeypatch, tmp_path):
    key = "V310-SHODAN-SECRET"
    seen = []

    def provider_file(_ctx, url, dest, **_kwargs):
        body = b'{"error":"Invalid API key"}'
        dest.write_bytes(body)
        return fetch.Acquisition(dest, len(body), "0" * 64, True), url, 401

    monkeypatch.setattr(fetch, "scoped_public_provider_get_file", provider_file)
    monkeypatch.setattr(
        probe, "_classified",
        lambda error: seen.append(error.filename) or "auth",
    )

    rows, total, error = probe._shodan_page(
        key, "http.favicon.hash", "1", 1, sink=tmp_path / "page.json",
    )
    assert (rows, total, error) == ([], None, "auth")
    assert seen == ["https://api.shodan.io/shodan/host/search"]
    assert key not in repr(seen)
