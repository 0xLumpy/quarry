from types import SimpleNamespace
import socket

import pytest

from quarry_recon import netguard, network_policy, notify

pytestmark = pytest.mark.offline


def test_notification_endpoints_are_canonical_https_and_fixed_for_public_channels():
    assert notify._canonical_endpoint(
        "https://hooks.slack.com/services/a/b/c", "slack",
    ) == "https://hooks.slack.com/services/a/b/c"
    assert notify._canonical_endpoint(
        "https://[fd00::1]:9443/quarry?key=secret", "webhook",
    ) == "https://[fd00::1]:9443/quarry?key=secret"
    with pytest.raises(notify.NotificationTransportError):
        notify._canonical_endpoint("http://hooks.slack.com/services/a", "slack")
    with pytest.raises(notify.NotificationTransportError):
        notify._canonical_endpoint("https://example.test/a", "slack")
    with pytest.raises(notify.NotificationTransportError):
        notify._canonical_endpoint("https://hooks.slack.com:0443/a", "slack")


def test_post_uses_bound_pinned_fetch_without_redirects_or_ambient_fallback(monkeypatch):
    calls = []
    monkeypatch.setattr(notify.fetch, "_network_scope", lambda _ctx: object())
    monkeypatch.setattr(
        notify.fetch, "scoped_operator_post",
        lambda ctx, url, payload, **kwargs:
            calls.append((ctx, url, payload, kwargs)) or 204,
    )

    run = object()
    notify._post(run, "webhook", "https://10.0.0.7:9443/quarry", {"ok": True})

    ctx, url, payload, kwargs = calls[0]
    assert ctx.run is run
    assert url == "https://10.0.0.7:9443/quarry"
    assert payload == b'{"ok":true}'
    assert kwargs["source_id"] == "notify.webhook"


def test_operator_authority_is_exact_and_private_only_for_the_configured_webhook(monkeypatch):
    scope = network_policy.NetworkPolicyScope(
        block_private_targets=False,
        apex_domains=("example.test",), own_ips=("192.0.2.10",),
        resolver_ips=("1.1.1.1",),
    )
    webhook = scope.operator_endpoint_authority(
        source_id="notify.webhook", host="hook.internal", port=9443,
    )
    assert scope.host_allowed(
        "hook.internal", source_id="notify.webhook",
        _operator_authority=webhook,
    )[0] == "allow"
    assert scope.host_allowed("other.internal", source_id="notify.webhook")[0] == "deny"
    monkeypatch.setattr(netguard, "own_ips", lambda: ("192.0.2.10",))
    assert scope.decide_peer(
        "10.0.0.7", 9443, socket.SOCK_STREAM, socket.IPPROTO_TCP,
        source_id="notify.webhook", _operator_authority=webhook,
    ).allowed
    with pytest.raises(network_policy.NetworkPolicyError, match="exact endpoint"):
        scope.decide_peer(
            "10.0.0.7", 443, socket.SOCK_STREAM, socket.IPPROTO_TCP,
            source_id="notify.webhook", _operator_authority=webhook,
        )


def test_public_notification_authority_rejects_private_rebinding(monkeypatch):
    scope = network_policy.NetworkPolicyScope(
        block_private_targets=False,
        apex_domains=("example.test",), own_ips=("192.0.2.10",),
        resolver_ips=("1.1.1.1",),
    )
    authority = scope.operator_endpoint_authority(
        source_id="notify.slack", host="hooks.slack.com", port=443,
    )
    assert scope.host_allowed(
        "hooks.slack.com", source_id="notify.slack",
        _operator_authority=authority,
    )[0] == "allow"
    monkeypatch.setattr(netguard, "own_ips", lambda: ("192.0.2.10",))
    decision = scope.decide_peer(
        "10.0.0.7", 443, socket.SOCK_STREAM, socket.IPPROTO_TCP,
        source_id="notify.slack", _operator_authority=authority,
    )
    assert not decision.allowed
    assert "public notification" in decision.reason


def test_notification_native_dns_uses_the_run_resolver_authority():
    scope = network_policy.NetworkPolicyScope(
        block_private_targets=False,
        apex_domains=("example.test",), own_ips=("192.0.2.10",),
        resolver_ips=("1.1.1.1",),
    )
    policy = scope.broker_policy(
        request_id="a" * 32, source_id="notify.webhook", tool="native-dns",
    )
    assert policy["resolver_mode"] == "mediated-public"
    assert policy["resolver_ips"] == ["1.1.1.1"]


def test_test_send_fails_closed_without_a_bound_run_context():
    with pytest.raises(notify.NotificationTransportError, match="bound run network policy"):
        notify.send_test()
