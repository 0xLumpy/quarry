"""Native public-provider HTTP must use the run-bound pinned transport."""
from __future__ import annotations

import io
from types import SimpleNamespace
import json
import urllib.request

import pytest

from quarry_recon import contract, fetch, network_dns, network_policy, store
from quarry_recon.phases import probe, vertical


pytestmark = pytest.mark.offline


def _ctx():
    scope = network_policy.NetworkPolicyScope(
        block_private_targets=False,
        requested_cidrs=("10.0.0.0/24",),
        apex_domains=("example.test",),
        own_ips=("192.0.2.10",),
        resolver_ips=("1.1.1.1",),
    )
    # The guard is the subject under test; event persistence is not.
    scope._trace = lambda _document: None
    return SimpleNamespace(
        run=SimpleNamespace(_network_policy_scope=scope, add=lambda *_args, **_kwargs: False),
        profile=SimpleNamespace(block_private_targets=False, http_rl=None),
    )


def _no_ambient_urlopen(*_args, **_kwargs):
    pytest.fail("native public-provider call reached ambient urllib.urlopen")


def test_vertical_provider_private_answer_is_refused_without_ambient_urllib(monkeypatch):
    ctx = _ctx()
    monkeypatch.setattr(network_dns, "resolve", lambda *_args, **_kwargs: (("10.0.0.2",), "ok"))
    monkeypatch.setattr(urllib.request, "urlopen", _no_ambient_urlopen)

    with pytest.raises(RuntimeError, match="refused by the run network scope"):
        vertical._certspotter("example.test", ctx=ctx)


def test_shodan_host_rebound_answer_is_refused_without_ambient_urllib(monkeypatch):
    ctx = _ctx()
    # A public provider treats a mixed/rebound answer as one refused resolution, never selecting the
    # apparently-public address after a private answer appears.
    monkeypatch.setattr(network_dns, "resolve", lambda *_args, **_kwargs: (("8.8.8.8", "10.0.0.2"), "ok"))
    monkeypatch.setattr(urllib.request, "urlopen", _no_ambient_urlopen)

    raw, code, err = probe._shodan_host_get(
        "https://api.shodan.io/shodan/host/8.8.8.8?key=x", 5, ctx=ctx,
    )
    assert (raw, code) == (b"", 0)
    assert err is not None and "refused by the run network scope" in str(err)


def test_public_provider_calls_use_their_exact_registered_lane_ids(monkeypatch):
    ctx = _ctx()
    vertical_seen = []

    def vertical_get(_ctx, url, *, source_id, **_kwargs):
        vertical_seen.append(source_id)
        if "censys" in url:
            body = {"result": {"hits": []}}
        elif "crt.sh" in url or "certspotter" in url:
            body = []
        else:
            body = {"subdomains": [], "more": False}
        return json.dumps(body).encode(), url, 200

    monkeypatch.setattr(vertical.fetch, "scoped_get", vertical_get)
    monkeypatch.setattr(urllib.request, "urlopen", _no_ambient_urlopen)
    assert vertical._censys({"token": "t", "org": "o"}, "example.test", ctx=ctx) == set()
    assert vertical._certspotter("example.test", ctx=ctx) == set()
    assert vertical._crtsh("example.test", ctx=ctx) == set()
    assert vertical._shodan_domain("example.test", "k", ctx=ctx) == set()
    assert vertical_seen == [
        "vertical.censys", "vertical.certspotter", "vertical.crtsh", "vertical.shosubgo",
    ]

    probe_seen = []

    def shodan_get(_ctx, url, *, source_id, **_kwargs):
        probe_seen.append(source_id)
        return b'{"total": 0}', url, 200

    monkeypatch.setattr(probe.fetch, "scoped_get", shodan_get)
    assert probe._shodan_count("k", "http.favicon.hash", "v", ctx=ctx,
                               source_id="probe.favicon") == (0, b'{"total": 0}', None)
    assert probe._shodan_count("k", "ssl.cert.fingerprint", "v", ctx=ctx,
                               source_id="probe.cert") == (0, b'{"total": 0}', None)
    assert probe_seen == ["probe.favicon", "probe.cert"]


def test_managed_shodan_receipt_and_result_metadata_redact_the_api_key(tmp_path, monkeypatch):
    class Response(io.BytesIO):
        status = 200
        headers = {}

    run = store.Run.create(tmp_path, "example.test", run_id="shodan-receipt-redaction")
    run.write_state("running")
    scope = network_policy.NetworkPolicyScope(
        block_private_targets=False, requested_cidrs=("10.0.0.0/24",),
        apex_domains=("example.test",), own_ips=("192.0.2.10",), resolver_ips=("1.1.1.1",),
    )
    scope._trace = lambda _document: None
    run._network_policy_scope = scope
    ctx = SimpleNamespace(
        run=run, profile=SimpleNamespace(http_rl=0, block_private_targets=False),
        scope=SimpleNamespace(active_allowed=lambda _host: True),
    )
    secret = "SHODAN-API-KEY-DO-NOT-PERSIST"
    url = f"https://api.shodan.io/shodan/host/search?key={secret}&query=ssl%3Ax&page=1"
    public_url = "https://api.shodan.io/shodan/host/search"
    dest = run.raw_path("probe", "shodan", "page.json")
    monkeypatch.setattr(network_dns, "resolve", lambda *_args, **_kwargs: (("8.8.8.8",), "ok"))
    monkeypatch.setattr(fetch, "_open_contact",
                        lambda *_args, **_kwargs: (200, {}, Response(b'{"total": 0, "matches": []}')))

    acquired, final, status = fetch.scoped_get_file(
        ctx, url, dest, governor=contract.DiskGovernor(reserve_bytes=0),
        source_id="probe.favicon", metadata_url=public_url,
    )

    assert status == 200 and acquired.complete, (status, acquired.disposition, acquired.error)
    receipt = json.loads(acquired._managed_receipt_snapshot.data)
    result_metadata = {
        "final": final, "acquisition_final": acquired.final,
        "error": acquired.error, "disposition": acquired.disposition,
    }
    assert receipt["ident"] == fetch.acquisition_identity(url)
    assert receipt["url"] == receipt["final"] == public_url
    assert secret not in json.dumps({"receipt": receipt, "result": result_metadata})
